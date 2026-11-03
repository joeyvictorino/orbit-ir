"""Tests for orbit_ir.access_pattern — access pattern anomaly detection."""

import json
from pathlib import Path

from orbit_ir.access_pattern import (
    AccessPatternReport,
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
    assert r.anomaly_count == 0
    assert r.events_analyzed == 0
    assert r.overall_risk == "low"


def test_off_hours_access(tmp_path):
    events = [
        {"timestamp": "2025-01-01T03:00:00Z", "agent_id": "a1", "actual_tool": "read"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, baseline_hours=(6, 22))
    off_hours = [a for a in r.anomalies if a.anomaly_type == "off_hours_access"]
    assert len(off_hours) == 1
    assert off_hours[0].agent_id == "a1"
    assert off_hours[0].details["hour"] == 3


def test_no_off_hours_when_in_range(tmp_path):
    events = [
        {"timestamp": "2025-01-01T12:00:00Z", "agent_id": "a1", "actual_tool": "read"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, baseline_hours=(6, 22))
    off_hours = [a for a in r.anomalies if a.anomaly_type == "off_hours_access"]
    assert len(off_hours) == 0


def test_frequency_spike(tmp_path):
    events = []
    # 10 events at hour 14, 1 event each at hours 10, 11, 12
    for i in range(10):
        events.append({"timestamp": f"2025-01-01T14:{i:02d}:00Z", "agent_id": "a1"})
    events.append({"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1"})
    events.append({"timestamp": "2025-01-01T11:00:00Z", "agent_id": "a1"})
    events.append({"timestamp": "2025-01-01T12:00:00Z", "agent_id": "a1"})
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    spikes = [a for a in r.anomalies if a.anomaly_type == "frequency_spike"]
    assert len(spikes) >= 1
    assert spikes[0].details["hour"] == 14


def test_admin_without_auth(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "actual_tool": "read_role",
         "resource": "iam/policy"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    admin = [a for a in r.anomalies if a.anomaly_type == "admin_without_auth"]
    assert len(admin) == 1


def test_admin_with_prior_auth(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "actual_tool": "authenticate",
         "effect": "auth-success", "resource": "auth/login"},
        {"timestamp": "2025-01-01T10:01:00Z", "agent_id": "a1", "actual_tool": "read_role",
         "resource": "iam/policy"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    admin = [a for a in r.anomalies if a.anomaly_type == "admin_without_auth"]
    assert len(admin) == 0


def test_repeated_failures(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "policy_decision": "denied"},
        {"timestamp": "2025-01-01T10:01:00Z", "agent_id": "a1", "policy_decision": "denied"},
        {"timestamp": "2025-01-01T10:02:00Z", "agent_id": "a1", "policy_decision": "denied"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    failures = [a for a in r.anomalies if a.anomaly_type == "repeated_failures"]
    assert len(failures) == 1
    assert failures[0].details["consecutive_failures"] == 3


def test_no_repeated_failures_when_success_between(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "policy_decision": "denied"},
        {"timestamp": "2025-01-01T10:01:00Z", "agent_id": "a1", "policy_decision": "allowed"},
        {"timestamp": "2025-01-01T10:02:00Z", "agent_id": "a1", "policy_decision": "denied"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    failures = [a for a in r.anomalies if a.anomaly_type == "repeated_failures"]
    assert len(failures) == 0


def test_rapid_credential_switch(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "credential_id": "cred-1"},
        {"timestamp": "2025-01-01T10:00:10Z", "agent_id": "a1", "credential_id": "cred-2"},
        {"timestamp": "2025-01-01T10:00:20Z", "agent_id": "a1", "credential_id": "cred-3"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    switches = [a for a in r.anomalies if a.anomaly_type == "rapid_credential_switch"]
    assert len(switches) == 1
    assert switches[0].details["credentials_count"] == 3


def test_no_rapid_switch_when_spread_out(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "credential_id": "cred-1"},
        {"timestamp": "2025-01-01T10:05:00Z", "agent_id": "a1", "credential_id": "cred-2"},
        {"timestamp": "2025-01-01T10:10:00Z", "agent_id": "a1", "credential_id": "cred-3"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    switches = [a for a in r.anomalies if a.anomaly_type == "rapid_credential_switch"]
    assert len(switches) == 0


def test_overall_risk_high(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "actual_tool": "read_role",
         "resource": "iam/admin"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.overall_risk == "high"  # admin_without_auth score=0.8


def test_multiple_agents(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1", "actual_tool": "read"},
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a2", "actual_tool": "write"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.agents_analyzed == 2


def test_hourly_distribution(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1"},
        {"timestamp": "2025-01-01T10:30:00Z", "agent_id": "a1"},
        {"timestamp": "2025-01-01T14:00:00Z", "agent_id": "a1"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.hourly_distribution[10] == 2
    assert r.hourly_distribution[14] == 1


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T03:00:00Z", "agent_id": "a1", "actual_tool": "scan"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Access Pattern Analysis" in text
    assert "Anomalies" in text
    assert "off_hours_access" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent_id": "a1"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "anomaly_count" in j
    assert "agents_analyzed" in j
    assert "hourly_distribution" in j


def test_deduplication(tmp_path):
    events = [
        {"timestamp": "2025-01-01T03:00:00Z", "agent_id": "a1", "actual_tool": "read"},
        {"timestamp": "2025-01-01T04:00:00Z", "agent_id": "a1", "actual_tool": "write"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    off_hours = [a for a in r.anomalies if a.anomaly_type == "off_hours_access"]
    # Deduplicated: only one off_hours anomaly per (type, agent)
    assert len(off_hours) == 1


def test_custom_baseline_hours(tmp_path):
    events = [
        {"timestamp": "2025-01-01T08:00:00Z", "agent_id": "a1"},
    ]
    _write_events(tmp_path, events)
    r_wide = analyze(tmp_path, baseline_hours=(0, 24))
    r_narrow = analyze(tmp_path, baseline_hours=(9, 17))
    off_wide = [a for a in r_wide.anomalies if a.anomaly_type == "off_hours_access"]
    off_narrow = [a for a in r_narrow.anomalies if a.anomaly_type == "off_hours_access"]
    assert len(off_wide) == 0
    assert len(off_narrow) == 1
