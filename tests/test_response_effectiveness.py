"""Tests for orbit_ir.response_effectiveness — response action effectiveness metrics."""

import json
from pathlib import Path

from orbit_ir.response_effectiveness import (
    ResponseEffectivenessReport,
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
    assert r.total_response_actions == 0
    assert r.effectiveness_score.grade == "F"


def test_full_response_lifecycle(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "investigate incident"},
        {"timestamp": "2025-01-01T10:15:00Z", "action": "contain threat"},
        {"timestamp": "2025-01-01T10:30:00Z", "action": "eradicate malware"},
        {"timestamp": "2025-01-01T11:00:00Z", "action": "recover system"},
        {"timestamp": "2025-01-01T11:05:00Z", "action": "notify team"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.total_response_actions == 6
    assert len(r.phases_covered) >= 5
    assert r.effectiveness_score.overall > 0.5


def test_detection_only(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:01:00Z", "action": "alert triggered"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert "detection" in r.phases_covered
    assert len(r.phases_missing) > 0
    assert r.effectiveness_score.phase_coverage < 0.5


def test_missing_phases_recommendations(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert len(r.recommendations) >= 1
    assert any("containment" in rec.lower() or "eradication" in rec.lower() for rec in r.recommendations)


def test_action_metrics(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:02:00Z", "action": "detect threat"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "contain threat"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    detect_metric = next((m for m in r.action_metrics if m.category == "detection"), None)
    assert detect_metric is not None
    assert detect_metric.action_count == 2
    assert detect_metric.unique_actions >= 1


def test_escalation_order(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "investigate"},
        {"timestamp": "2025-01-01T10:10:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.effectiveness_score.escalation_speed >= 0.5


def test_escalation_out_of_order(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "recover system"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "detect anomaly"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.effectiveness_score.escalation_speed < 1.0


def test_non_response_events(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "login"},
        {"timestamp": "2025-01-01T10:01:00Z", "action": "read file"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.total_response_actions == 0
    assert r.effectiveness_score.overall < 0.5


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Response Effectiveness Report" in text
    assert "Phases" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "total_events" in j
    assert "effectiveness_score" in j
    assert "action_metrics" in j


def test_action_density(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:01:00Z", "action": "investigate cause"},
        {"timestamp": "2025-01-01T10:02:00Z", "action": "contain threat"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.effectiveness_score.action_density == 1.0
