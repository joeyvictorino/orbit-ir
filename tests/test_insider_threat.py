"""Tests for insider threat pattern detection."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.insider_threat import (
    analyze,
    format_text,
    format_json,
    _load_events,
    _is_exfil_action,
    _is_privilege_action,
    _is_recon_action,
    _parse_hour,
    _classify_severity,
    _classify_confidence,
    _compute_risk_score,
    ThreatIndicator,
)


def _make_event(agent="agent-1", tool="read_file", ts="2025-01-15T10:00:00Z", resource="", **extra):
    ev = {"agent_id": agent, "tool": tool, "timestamp": ts, "resource": resource, **extra}
    return ev


class TestHelpers:
    def test_is_exfil_action_positive(self):
        assert _is_exfil_action("upload")
        assert _is_exfil_action("send_data")
        assert _is_exfil_action("push_data")
        assert _is_exfil_action("sync_external")

    def test_is_exfil_action_negative(self):
        assert not _is_exfil_action("read_file")
        assert not _is_exfil_action("list_dir")

    def test_is_privilege_action_positive(self):
        assert _is_privilege_action("create_role")
        assert _is_privilege_action("grant_permission")
        assert _is_privilege_action("modify_acl")
        assert _is_privilege_action("assume_role")

    def test_is_privilege_action_keyword(self):
        assert _is_privilege_action("update_role_binding")
        assert _is_privilege_action("manage_credential_store")

    def test_is_privilege_action_negative(self):
        assert not _is_privilege_action("read_file")

    def test_is_recon_action_positive(self):
        assert _is_recon_action("list_users")
        assert _is_recon_action("enumerate_services")
        assert _is_recon_action("scan_ports")

    def test_is_recon_action_negative(self):
        assert not _is_recon_action("write_file")

    def test_parse_hour(self):
        assert _parse_hour("2025-01-15T14:30:00Z") == 14
        assert _parse_hour("2025-01-15T03:00:00.123Z") == 3
        assert _parse_hour("2025-01-15T23:59:59") == 23
        assert _parse_hour("not-a-timestamp") is None

    def test_classify_severity(self):
        inds = [ThreatIndicator("", "", "", "slow-exfiltration", "", "", "", "", 0)] * 5
        assert _classify_severity(inds, "slow-exfiltration") == "critical"
        inds2 = [ThreatIndicator("", "", "", "", "", "", "", "", 0)] * 3
        assert _classify_severity(inds2, "other") == "high"
        inds1 = [ThreatIndicator("", "", "", "", "", "", "", "", 0)]
        assert _classify_severity(inds1, "other") == "low"

    def test_classify_confidence(self):
        inds5 = [ThreatIndicator("", "", "", "", "", "", "", "", 0)] * 5
        assert _classify_confidence(inds5, "any") == "high"
        inds3 = [ThreatIndicator("", "", "", "", "", "", "", "", 0)] * 3
        assert _classify_confidence(inds3, "any") == "medium"
        inds1 = [ThreatIndicator("", "", "", "", "", "", "", "", 0)]
        assert _classify_confidence(inds1, "any") == "low"

    def test_compute_risk_score(self):
        inds = [ThreatIndicator("", "", "", "", "", "", "", "", 0)] * 10
        score = _compute_risk_score(inds, "critical", "high")
        assert score == 1.0
        score_low = _compute_risk_score(inds[:1], "low", "low")
        assert score_low < 0.2


class TestSlowExfiltration:
    def test_detects_multiple_exfil_actions(self):
        events = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z", resource="s3://bucket")
            for i in range(5)
        ]
        report = analyze(events)
        assert report.summary.total_patterns >= 1
        types = [p.pattern_type for p in report.patterns]
        assert "slow-exfiltration" in types

    def test_single_exfil_not_flagged(self):
        events = [_make_event(tool="upload")]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "slow-exfiltration" not in types


class TestPrivilegeAccumulation:
    def test_detects_privilege_accumulation(self):
        events = [
            _make_event(tool="create_role", ts="2025-01-15T10:00:00Z"),
            _make_event(tool="grant_permission", ts="2025-01-15T10:01:00Z"),
            _make_event(tool="assume_role", ts="2025-01-15T10:02:00Z"),
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "privilege-accumulation" in types

    def test_single_privilege_not_flagged(self):
        events = [_make_event(tool="create_role")]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "privilege-accumulation" not in types


class TestAfterHours:
    def test_detects_after_hours_activity(self):
        events = [
            _make_event(tool="read_file", ts=f"2025-01-15T23:0{i}:00Z")
            for i in range(5)
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "after-hours-activity" in types

    def test_business_hours_not_flagged(self):
        events = [
            _make_event(tool="read_file", ts=f"2025-01-15T1{i}:00:00Z")
            for i in range(5)
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "after-hours-activity" not in types

    def test_early_morning_flagged(self):
        events = [
            _make_event(tool="read_file", ts=f"2025-01-15T03:0{i}:00Z")
            for i in range(4)
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "after-hours-activity" in types


class TestUnrelatedAccess:
    def test_detects_cross_category_access(self):
        events = [
            _make_event(resource="finance/budget.xlsx"),
            _make_event(resource="hr/employees.csv"),
            _make_event(resource="engineering/code.py"),
            _make_event(resource="legal/contracts.pdf"),
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "unrelated-resource-access" in types

    def test_same_category_not_flagged(self):
        events = [
            _make_event(resource="engineering/a.py"),
            _make_event(resource="engineering/b.py"),
            _make_event(resource="engineering/c.py"),
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "unrelated-resource-access" not in types


class TestReconSweep:
    def test_detects_recon_sweep(self):
        events = [
            _make_event(tool="list_users", ts="2025-01-15T10:00:00Z"),
            _make_event(tool="list_roles", ts="2025-01-15T10:01:00Z"),
            _make_event(tool="list_secrets", ts="2025-01-15T10:02:00Z"),
        ]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "reconnaissance-sweep" in types

    def test_single_recon_not_flagged(self):
        events = [_make_event(tool="list_users")]
        report = analyze(events)
        types = [p.pattern_type for p in report.patterns]
        assert "reconnaissance-sweep" not in types


class TestAnalyze:
    def test_empty_events(self):
        report = analyze([])
        assert report.summary.total_patterns == 0
        assert report.agents_flagged == []

    def test_control_events_included(self):
        events = []
        control = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z")
            for i in range(3)
        ]
        report = analyze(events, control)
        types = [p.pattern_type for p in report.patterns]
        assert "slow-exfiltration" in types

    def test_risk_score_ordering(self):
        events = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z", resource="s3://bucket")
            for i in range(8)
        ]
        events.extend([
            _make_event(agent="agent-2", tool="list_users", ts="2025-01-15T10:00:00Z"),
            _make_event(agent="agent-2", tool="scan_ports", ts="2025-01-15T10:01:00Z"),
        ])
        report = analyze(events)
        if len(report.patterns) >= 2:
            assert report.patterns[0].risk_score >= report.patterns[1].risk_score

    def test_multiple_agents(self):
        events = []
        for agent in ("a1", "a2"):
            events.extend([
                _make_event(agent=agent, tool="upload", ts=f"2025-01-15T10:0{i}:00Z")
                for i in range(3)
            ])
        report = analyze(events)
        assert report.summary.agents_flagged >= 2

    def test_summary_by_type(self):
        events = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z")
            for i in range(3)
        ]
        report = analyze(events)
        assert "slow-exfiltration" in report.summary.by_type


class TestFormatText:
    def test_basic_format(self):
        events = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z", resource="bucket")
            for i in range(3)
        ]
        report = analyze(events)
        text = format_text(report)
        assert "Insider Threat Detection Report" in text
        assert "agent-1" in text

    def test_empty_report(self):
        report = analyze([])
        text = format_text(report)
        assert "Total patterns:         0" in text


class TestFormatJson:
    def test_valid_json(self):
        events = [
            _make_event(tool="upload", ts=f"2025-01-15T10:0{i}:00Z")
            for i in range(3)
        ]
        report = analyze(events)
        output = format_json(report)
        data = json.loads(output)
        assert "patterns" in data
        assert "summary" in data
        assert "agents_flagged" in data

    def test_empty_json(self):
        report = analyze([])
        data = json.loads(format_json(report))
        assert data["summary"]["total_patterns"] == 0


class TestLoadEvents:
    def test_load_from_directory(self, tmp_path):
        events = [
            {"agent_id": "a1", "tool": "upload", "timestamp": "2025-01-15T10:00:00Z"},
            {"agent_id": "a1", "tool": "send", "timestamp": "2025-01-15T10:01:00Z"},
        ]
        (tmp_path / "transcripts.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events), encoding="utf-8"
        )
        loaded_events, loaded_control = _load_events(tmp_path)
        assert len(loaded_events) == 2

    def test_load_control_plane(self, tmp_path):
        control = [{"agent_id": "a1", "tool": "upload", "timestamp": "2025-01-15T10:00:00Z"}]
        (tmp_path / "control_plane.jsonl").write_text(
            json.dumps(control[0]), encoding="utf-8"
        )
        loaded_events, loaded_control = _load_events(tmp_path)
        assert len(loaded_control) == 1

    def test_load_empty_dir(self, tmp_path):
        events, control = _load_events(tmp_path)
        assert events == []
        assert control == []
