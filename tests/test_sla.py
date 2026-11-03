"""Tests for orbit_ir.sla — response time SLA measurement."""

import json
from pathlib import Path

from orbit_ir.sla import (
    SLAReport,
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
    assert r.incidents_measured == 0
    assert r.overall_compliance_rate == 1.0


def test_full_incident_lifecycle(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "acknowledge incident"},
        {"timestamp": "2025-01-01T10:10:00Z", "action": "notify team"},
        {"timestamp": "2025-01-01T10:30:00Z", "action": "contain threat"},
        {"timestamp": "2025-01-01T12:00:00Z", "action": "resolve incident"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.incidents_measured >= 1
    inc = r.incidents[0]
    ack = next((m for m in inc.measurements if "acknowledge" in m.metric.lower()), None)
    assert ack is not None
    assert ack.actual_minutes == 5.0
    assert ack.met is True


def test_sla_violation(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect threat"},
        {"timestamp": "2025-01-01T10:30:00Z", "action": "acknowledge"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_acknowledge_minutes": 10})
    assert r.incidents_measured >= 1
    inc = r.incidents[0]
    ack = next((m for m in inc.measurements if "acknowledge" in m.metric.lower()), None)
    assert ack is not None
    assert ack.met is False
    assert ack.actual_minutes == 30.0


def test_comfortable_sla(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:01:00Z", "action": "triage incident"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_acknowledge_minutes": 60})
    inc = r.incidents[0]
    ack = next((m for m in inc.measurements if "acknowledge" in m.metric.lower()), None)
    assert ack is not None
    assert ack.assessment == "comfortable"


def test_critical_violation(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T14:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_contain_minutes": 60})
    inc = r.incidents[0]
    contain = next((m for m in inc.measurements if "contain" in m.metric.lower()), None)
    assert contain is not None
    assert contain.assessment == "critical_violation"
    assert contain.actual_minutes == 240.0


def test_no_response_data(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect anomaly"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "scan system"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_contain_minutes": 60})
    inc = r.incidents[0]
    contain = next((m for m in inc.measurements if "contain" in m.metric.lower()), None)
    assert contain is not None
    assert contain.assessment == "no_data"
    assert contain.actual_minutes is None


def test_compliance_rate(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "acknowledge"},
        {"timestamp": "2025-01-01T10:20:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={
        "time_to_acknowledge_minutes": 10,
        "time_to_contain_minutes": 30,
    })
    assert r.overall_compliance_rate == 1.0


def test_partial_compliance(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "acknowledge"},
        {"timestamp": "2025-01-01T12:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={
        "time_to_acknowledge_minutes": 10,
        "time_to_contain_minutes": 30,
    })
    inc = r.incidents[0]
    assert inc.compliance_score == 0.5


def test_custom_sla_targets(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:02:00Z", "action": "acknowledge"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_acknowledge_minutes": 5})
    assert r.sla_targets["time_to_acknowledge_minutes"] == 5
    inc = r.incidents[0]
    ack = next((m for m in inc.measurements if "acknowledge" in m.metric.lower()), None)
    assert ack.met is True


def test_worst_violations(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T12:00:00Z", "action": "acknowledge"},
        {"timestamp": "2025-01-01T14:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={
        "time_to_acknowledge_minutes": 10,
        "time_to_contain_minutes": 30,
    })
    assert len(r.worst_violations) >= 1
    assert r.worst_violations[0].met is False


def test_average_response_times(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:10:00Z", "action": "acknowledge"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={"time_to_acknowledge_minutes": 60})
    assert "Time to acknowledge" in r.average_response_minutes
    assert r.average_response_minutes["Time to acknowledge"] == 10.0


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:10:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Response Time SLA Report" in text
    assert "SLA Targets" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "total_events" in j
    assert "incidents" in j
    assert "sla_targets" in j


def test_resolve_sla(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T10:30:00Z", "action": "contain"},
        {"timestamp": "2025-01-01T13:00:00Z", "action": "resolve"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, sla_targets={
        "time_to_contain_minutes": 60,
        "time_to_resolve_minutes": 240,
    })
    inc = r.incidents[0]
    resolve = next((m for m in inc.measurements if "resolve" in m.metric.lower()), None)
    assert resolve is not None
    assert resolve.actual_minutes == 180.0
    assert resolve.met is True
