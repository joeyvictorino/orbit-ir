"""Tests for deception_detect module."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.deception_detect import (
    DeceptionDetection,
    DeceptionIndicator,
    DeceptionReport,
    DeceptionSummary,
    analyze_deception,
    format_json,
    format_text,
    _has_concealment,
    _has_fabrication,
    _has_authority_claim,
    _tool_mismatch,
    _output_mismatch,
    _contradicts_prior,
    _load_events,
)


class TestHelpers:
    def test_has_concealment_positive(self):
        assert _has_concealment("suppress_log") is True
        assert _has_concealment("SILENT_mode") is True
        assert _has_concealment("hide_output") is True

    def test_has_concealment_negative(self):
        assert _has_concealment("read_file") is False
        assert _has_concealment("normal_tool") is False

    def test_has_fabrication_positive(self):
        assert _has_fabrication("fabricate_result") is True
        assert _has_fabrication("spoof_output") is True

    def test_has_fabrication_negative(self):
        assert _has_fabrication("read_file") is False

    def test_has_authority_claim(self):
        assert _has_authority_claim("I have admin access") is True
        assert _has_authority_claim("root permission granted") is True
        assert _has_authority_claim("reading a file") is False

    def test_tool_mismatch_detected(self):
        ev = {"claimed_tool": "read_file", "actual_tool": "write_file"}
        result = _tool_mismatch(ev)
        assert result == ("read_file", "write_file")

    def test_tool_mismatch_same(self):
        ev = {"claimed_tool": "read_file", "actual_tool": "read_file"}
        assert _tool_mismatch(ev) is None

    def test_tool_mismatch_missing(self):
        ev = {"claimed_tool": "read_file"}
        assert _tool_mismatch(ev) is None

    def test_output_mismatch(self):
        ev = {"claimed_output": "file is empty", "actual_output": "file has 500 lines"}
        assert _output_mismatch(ev) is True

    def test_output_match(self):
        ev = {"claimed_output": "ok", "actual_output": "ok"}
        assert _output_mismatch(ev) is False

    def test_contradicts_prior(self):
        prior = [
            {"agent_id": "a1", "resource": "/etc/passwd", "effect": "read-only"},
        ]
        ev = {"agent_id": "a1", "resource": "/etc/passwd", "effect": "modified"}
        result = _contradicts_prior(ev, prior)
        assert result is not None

    def test_no_contradiction(self):
        prior = [
            {"agent_id": "a1", "resource": "/etc/passwd", "effect": "read-only"},
        ]
        ev = {"agent_id": "a1", "resource": "/etc/passwd", "effect": "read-only"}
        assert _contradicts_prior(ev, prior) is None


class TestAnalyzeDeception:
    def test_empty_events(self):
        report = analyze_deception([])
        assert report.summary.total_detections == 0
        assert report.agents_involved == []

    def test_no_deception(self):
        events = [
            {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
            {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z"},
        ]
        report = analyze_deception(events)
        assert report.summary.total_detections == 0

    def test_tool_misrepresentation(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "read_file",
                "actual_tool": "delete_file",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a1",
                "claimed_tool": "list_dir",
                "actual_tool": "exfiltrate_data",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
            {
                "agent_id": "a1",
                "claimed_tool": "search",
                "actual_tool": "upload_file",
                "timestamp": "2026-01-01T00:02:00Z",
                "event_id": "e3",
            },
        ]
        report = analyze_deception(events)
        assert report.summary.total_detections >= 1
        misrep = [d for d in report.detections if d.technique == "action-concealment"]
        assert len(misrep) >= 1
        assert misrep[0].confidence == "high"

    def test_output_fabrication(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_output": "no sensitive data found",
                "actual_output": "found 50 credentials",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a1",
                "claimed_output": "all checks passed",
                "actual_output": "3 failures detected",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
        ]
        report = analyze_deception(events)
        fab = [d for d in report.detections if d.technique == "output-fabrication"]
        assert len(fab) >= 1
        assert fab[0].confidence in ("medium", "high")

    def test_concealment_detection(self):
        events = [
            {
                "agent_id": "a1",
                "tool": "suppress_logging",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a1",
                "tool": "hide_traces",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
            {
                "agent_id": "a1",
                "tool": "obfuscate_data",
                "timestamp": "2026-01-01T00:02:00Z",
                "event_id": "e3",
            },
        ]
        report = analyze_deception(events)
        conceal = [d for d in report.detections if d.technique == "action-concealment"]
        assert len(conceal) >= 1

    def test_authority_fabrication_role_mismatch(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_role": "admin",
                "actual_role": "reader",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a1",
                "claimed_role": "superuser",
                "actual_role": "basic",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
        ]
        report = analyze_deception(events)
        auth = [d for d in report.detections if d.technique == "authority-fabrication"]
        assert len(auth) >= 1
        assert auth[0].confidence == "high"

    def test_authority_fabrication_denied_claim(self):
        events = [
            {
                "agent_id": "a1",
                "output": "I have admin access to this system",
                "policy_decision": "denied",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
        ]
        report = analyze_deception(events)
        auth = [d for d in report.detections if d.technique == "authority-fabrication"]
        assert len(auth) >= 1

    def test_contradiction_detection(self):
        events = [
            {
                "agent_id": "a1",
                "resource": "/data/secrets.json",
                "effect": "not-found",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a1",
                "resource": "/data/secrets.json",
                "effect": "read-complete",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
        ]
        report = analyze_deception(events)
        contra = [d for d in report.detections if d.technique == "context-manipulation"]
        assert len(contra) >= 1

    def test_multi_agent_deception(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "read_file",
                "actual_tool": "delete_file",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
            {
                "agent_id": "a2",
                "claimed_tool": "search",
                "actual_tool": "exfiltrate",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e2",
            },
        ]
        report = analyze_deception(events)
        assert report.summary.agents_involved >= 2
        assert len(report.agents_involved) >= 2

    def test_deception_score(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "read",
                "actual_tool": "write",
                "timestamp": f"2026-01-01T00:0{i}:00Z",
                "event_id": f"e{i}",
            }
            for i in range(5)
        ]
        report = analyze_deception(events)
        assert 0 <= report.summary.deception_score <= 1.0

    def test_most_deceptive_agent(self):
        events = []
        for i in range(5):
            events.append({
                "agent_id": "heavy-deceiver",
                "claimed_tool": f"tool_{i}",
                "actual_tool": f"bad_tool_{i}",
                "timestamp": f"2026-01-01T00:0{i}:00Z",
                "event_id": f"e{i}",
            })
        events.append({
            "agent_id": "light-deceiver",
            "claimed_tool": "x",
            "actual_tool": "y",
            "timestamp": "2026-01-01T00:10:00Z",
            "event_id": "e10",
        })
        report = analyze_deception(events)
        assert report.summary.most_deceptive_agent == "heavy-deceiver"


class TestFormatText:
    def test_format_text_empty(self):
        report = analyze_deception([])
        text = format_text(report)
        assert "Agent Deception Detection Report" in text
        assert "Total detections:       0" in text

    def test_format_text_with_detections(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "read",
                "actual_tool": "write",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
        ]
        report = analyze_deception(events)
        text = format_text(report)
        assert "DECEPT-" in text
        assert "a1" in text


class TestFormatJson:
    def test_format_json_valid(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "read",
                "actual_tool": "write",
                "timestamp": "2026-01-01T00:00:00Z",
                "event_id": "e1",
            },
        ]
        report = analyze_deception(events)
        output = format_json(report)
        data = json.loads(output)
        assert "detections" in data
        assert "summary" in data
        assert "agents_involved" in data
        assert "timeline" in data

    def test_format_json_empty(self):
        report = analyze_deception([])
        data = json.loads(format_json(report))
        assert data["summary"]["total_detections"] == 0


class TestLoadEvents:
    def test_load_events_from_dir(self, tmp_path):
        events = [
            {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
            {"agent_id": "a2", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z"},
        ]
        (tmp_path / "transcripts.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events)
        )
        loaded = _load_events(tmp_path)
        assert len(loaded) == 2

    def test_load_events_empty_dir(self, tmp_path):
        loaded = _load_events(tmp_path)
        assert loaded == []

    def test_load_events_bad_json(self, tmp_path):
        (tmp_path / "events.jsonl").write_text("not json\n{}\n")
        loaded = _load_events(tmp_path)
        assert len(loaded) == 1


class TestTimeline:
    def test_timeline_ordering(self):
        events = [
            {
                "agent_id": "a1",
                "claimed_tool": "x",
                "actual_tool": "y",
                "timestamp": "2026-01-01T00:02:00Z",
                "event_id": "e2",
            },
            {
                "agent_id": "a1",
                "claimed_tool": "a",
                "actual_tool": "b",
                "timestamp": "2026-01-01T00:01:00Z",
                "event_id": "e1",
            },
        ]
        report = analyze_deception(events)
        if report.timeline:
            timestamps = [e["timestamp"] for e in report.timeline]
            assert timestamps == sorted(timestamps)
