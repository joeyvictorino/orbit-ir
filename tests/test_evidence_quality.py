"""Tests for orbit_ir.evidence_quality — evidence completeness and quality scoring."""

import json
from pathlib import Path

from orbit_ir.evidence_quality import (
    EvidenceQualityReport,
    analyze,
    format_json,
    format_text,
)


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp_path


def test_empty_evidence(tmp_path):
    r = analyze(tmp_path)
    assert r.total_events == 0
    assert r.quality_score.overall == 0
    assert r.quality_score.grade == "F"


def test_complete_events(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly", "agent_id": "a1",
         "type": "alert", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "status": "open"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "investigate", "agent_id": "a2",
         "type": "response", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "status": "in_progress"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.total_events == 2
    assert r.quality_score.completeness > 0.5
    assert r.quality_score.grade in ("A", "B", "C")


def test_missing_required_fields(tmp_path):
    events = [
        {"agent_id": "a1"},
        {"agent_id": "a2"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.quality_score.completeness < 0.5
    assert any("timestamp" in rec for rec in r.recommendations)


def test_field_coverage(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:01:00Z"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    ts_cov = next(fc for fc in r.field_coverage if fc.field_name == "timestamp")
    assert ts_cov.coverage_pct == 100.0
    action_cov = next(fc for fc in r.field_coverage if fc.field_name == "action")
    assert action_cov.coverage_pct == 50.0


def test_consistency_chronological(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "first"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "second"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    chrono = next(c for c in r.consistency_checks if c.check_name == "chronological_order")
    assert chrono.passed is True


def test_consistency_out_of_order(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:10:00Z", "action": "late"},
        {"timestamp": "2025-01-01T10:00:00Z", "action": "early"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    chrono = next(c for c in r.consistency_checks if c.check_name == "chronological_order")
    assert chrono.passed is False


def test_duplicate_detection(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    dup = next(c for c in r.consistency_checks if c.check_name == "no_duplicates")
    assert dup.passed is False


def test_no_duplicates(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:01:00Z", "action": "respond"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    dup = next(c for c in r.consistency_checks if c.check_name == "no_duplicates")
    assert dup.passed is True


def test_recommendations(tmp_path):
    events = [
        {"agent_id": "a1"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert len(r.recommendations) >= 1


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Evidence Quality Report" in text
    assert "Field Coverage" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "total_events" in j
    assert "quality_score" in j


def test_grade_scaling(tmp_path):
    events = [
        {"timestamp": f"2025-01-01T10:{i:02d}:00Z", "action": f"action_{i}",
         "agent_id": f"a{i}", "type": "alert", "src_ip": "10.0.0.1",
         "dst_ip": "10.0.0.2", "status": "ok",
         "severity": "high", "category": "threat", "description": "test",
         "reason": "detected", "tool": "scanner", "target": "host1"}
        for i in range(20)
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.quality_score.grade in ("A", "B")
