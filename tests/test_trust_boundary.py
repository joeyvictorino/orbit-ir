"""Tests for trust boundary crossing detection."""
from __future__ import annotations

import json

from orbit_ir.trust_boundary import (
    analyze_trust_boundaries,
    format_text,
    format_json,
    _load_events,
    _classify_zone,
    _classify_privilege,
    _crossing_severity,
    _compute_risk,
    BoundaryCrossing,
    AgentBoundaryProfile,
    TrustBoundaryReport,
    TrustBoundarySummary,
)


def _ev(agent_id, tool="read_file", resource="", timestamp="2025-01-01T00:00:00Z", **kwargs):
    return {"agent_id": agent_id, "tool": tool, "resource": resource, "timestamp": timestamp, **kwargs}


class TestClassifyZone:
    def test_filesystem(self):
        assert _classify_zone({"resource": "/etc/passwd"}) == "filesystem"

    def test_cloud(self):
        assert _classify_zone({"resource": "s3://bucket/key"}) == "cloud"

    def test_external(self):
        assert _classify_zone({"resource": "https://example.com/api"}) == "external"

    def test_internal(self):
        assert _classify_zone({"resource": "10.0.0.1:8080"}) == "internal"

    def test_database(self):
        assert _classify_zone({"resource": "postgres://db/table"}) == "database"

    def test_sensitive(self):
        assert _classify_zone({"resource": ".ssh/id_rsa"}) == "sensitive"

    def test_standard(self):
        assert _classify_zone({"resource": "my_data.txt"}) == "standard"


class TestClassifyPrivilege:
    def test_read_only(self):
        assert _classify_privilege({"tool": "read_file"}) == 0

    def test_standard(self):
        assert _classify_privilege({"tool": "create_item"}) == 1

    def test_elevated(self):
        assert _classify_privilege({"tool": "write_file"}) == 2

    def test_admin(self):
        assert _classify_privilege({"tool": "sudo"}) == 3

    def test_sensitive_resource_elevates(self):
        assert _classify_privilege({"tool": "get", "resource": ".ssh/id_rsa"}) == 2


class TestCrossingSeverity:
    def test_large_priv_jump_critical(self):
        sev = _crossing_severity("standard", "cloud", 0, 2, {})
        assert sev == "critical"

    def test_into_sensitive_critical(self):
        sev = _crossing_severity("standard", "sensitive", 1, 1, {})
        assert sev == "critical"

    def test_escalation_to_cloud_high(self):
        sev = _crossing_severity("standard", "cloud", 0, 1, {})
        assert sev == "high"

    def test_standard_to_external_high(self):
        sev = _crossing_severity("standard", "external", 1, 1, {})
        assert sev == "high"

    def test_small_escalation_medium(self):
        sev = _crossing_severity("filesystem", "filesystem", 0, 1, {})
        assert sev == "medium"

    def test_zone_change_medium(self):
        sev = _crossing_severity("internal", "filesystem", 1, 1, {})
        assert sev == "medium"


class TestComputeRisk:
    def test_zero_risk(self):
        assert _compute_risk(0, 0, 0, 0) == 0.0

    def test_max_risk_capped(self):
        risk = _compute_risk(10, 20, 10, 3)
        assert risk <= 1.0

    def test_escalation_weighted_highest(self):
        r_no_esc = _compute_risk(2, 2, 0, 1)
        r_esc = _compute_risk(2, 2, 2, 1)
        assert r_esc > r_no_esc


class TestAnalyzeTrustBoundaries:
    def test_empty_events(self):
        report = analyze_trust_boundaries([])
        assert report.summary.total_crossings == 0
        assert report.summary.unique_agents == 0

    def test_single_zone_no_crossings(self):
        events = [
            _ev("a1", "read_file", "/etc/config1", "2025-01-01T00:01:00Z"),
            _ev("a1", "read_file", "/etc/config2", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert report.summary.total_crossings == 0

    def test_zone_crossing_detected(self):
        events = [
            _ev("a1", "read_file", "/etc/config", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://bucket/exfil", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert report.summary.total_crossings >= 1
        assert report.crossings[0].from_zone == "filesystem"
        assert report.crossings[0].to_zone == "cloud"

    def test_privilege_escalation(self):
        events = [
            _ev("a1", "read_file", "data.txt", "2025-01-01T00:01:00Z"),
            _ev("a1", "sudo", "/etc/shadow", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        esc_crossings = [c for c in report.crossings if c.to_privilege > c.from_privilege]
        assert len(esc_crossings) >= 1

    def test_multiple_agents(self):
        events = [
            _ev("a1", "read_file", "/etc/x", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://b/k", "2025-01-01T00:02:00Z"),
            _ev("a2", "query", "data.txt", "2025-01-01T00:01:00Z"),
            _ev("a2", "write_file", "/etc/shadow", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert report.summary.unique_agents == 2
        assert len(report.agent_profiles) == 2

    def test_crossings_sorted_by_severity(self):
        events = [
            _ev("a1", "read_file", "safe.txt", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://b/k", "2025-01-01T00:02:00Z"),
            _ev("a1", "sudo", ".ssh/id_rsa", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        if len(report.crossings) >= 2:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for i in range(len(report.crossings) - 1):
                assert severity_order[report.crossings[i].severity] <= severity_order[report.crossings[i + 1].severity]

    def test_agent_profiles_ranked_by_risk(self):
        events = [
            _ev("risky", "read_file", "/etc/x", "2025-01-01T00:01:00Z"),
            _ev("risky", "sudo", "s3://secret", "2025-01-01T00:02:00Z"),
            _ev("risky", "deploy", "https://prod.com", "2025-01-01T00:03:00Z"),
            _ev("safe", "read_file", "doc.txt", "2025-01-01T00:01:00Z"),
            _ev("safe", "read_file", "doc2.txt", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert report.agent_profiles[0].risk_score >= report.agent_profiles[-1].risk_score

    def test_summary_zone_pairs(self):
        events = [
            _ev("a1", "read_file", "/etc/x", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://b/k", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert len(report.summary.by_zone_pair) >= 1

    def test_no_agent_id_skipped(self):
        events = [{"tool": "read_file", "timestamp": "2025-01-01T00:01:00Z"}]
        report = analyze_trust_boundaries(events)
        assert report.summary.unique_agents == 0

    def test_escalation_count(self):
        events = [
            _ev("a1", "read_file", "safe.txt", "2025-01-01T00:01:00Z"),
            _ev("a1", "sudo", ".ssh/key", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        assert report.summary.escalation_events >= 1

    def test_crossing_ids_unique(self):
        events = [
            _ev("a1", "read_file", "/etc/x", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://b", "2025-01-01T00:02:00Z"),
            _ev("a1", "query", "postgres://db", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        ids = [c.crossing_id for c in report.crossings]
        assert len(ids) == len(set(ids))


class TestFormatText:
    def test_empty_report(self):
        report = TrustBoundaryReport(
            crossings=[], agent_profiles=[],
            summary=TrustBoundarySummary(total_crossings=0, unique_agents=0, zones_involved=0, escalation_events=0),
        )
        text = format_text(report)
        assert "Trust Boundary Crossing Report" in text
        assert "Total crossings:        0" in text

    def test_with_crossings(self):
        events = [
            _ev("a1", "read_file", "/etc/config", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://bucket/data", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        text = format_text(report)
        assert "a1" in text
        assert "TB-" in text


class TestFormatJson:
    def test_empty_json(self):
        report = TrustBoundaryReport(
            crossings=[], agent_profiles=[],
            summary=TrustBoundarySummary(total_crossings=0, unique_agents=0, zones_involved=0, escalation_events=0),
        )
        output = format_json(report)
        data = json.loads(output)
        assert data["crossings"] == []
        assert data["summary"]["total_crossings"] == 0

    def test_json_structure(self):
        events = [
            _ev("a1", "read_file", "/etc/config", "2025-01-01T00:01:00Z"),
            _ev("a1", "upload", "s3://bucket/data", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        output = format_json(report)
        data = json.loads(output)
        assert "crossings" in data
        assert "agent_profiles" in data
        assert "summary" in data

    def test_json_roundtrip(self):
        events = [
            _ev("a1", "read_file", "/etc/x", "2025-01-01T00:01:00Z"),
            _ev("a1", "sudo", "s3://secret", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_trust_boundaries(events)
        output = format_json(report)
        data = json.loads(output)
        assert isinstance(data["summary"]["total_crossings"], int)


class TestLoadEvents:
    def test_load_from_dir(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"agent_id": "a1"}\n')
        events = _load_events(tmp_path)
        assert len(events) == 1

    def test_load_missing(self, tmp_path):
        events = _load_events(tmp_path / "nope")
        assert events == []
