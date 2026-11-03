"""Tests for agent collusion detection."""
from orbit_ir.agent_collusion import (
    analyze,
    format_text,
    format_json,
    _parse_timestamp,
    _detect_synchronized_actions,
    _detect_shared_targets,
    _detect_coordinated_escalation,
    _detect_credential_sharing,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_indicators == 0
    assert r.agents_involved == []


def test_no_collusion():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "read", "credential_id": ""},
    ]
    r = analyze(events)
    assert r.summary.total_indicators == 0


def test_synchronized_actions():
    events = []
    for i in range(5):
        events.append({"agent_id": "a1", "timestamp": f"2025-01-01T00:0{i}:00Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
        events.append({"agent_id": "a2", "timestamp": f"2025-01-01T00:0{i}:02Z",
                        "resource": f"s{i}", "effect": "action", "credential_id": ""})
    r = analyze(events, sync_window=5.0)
    assert any(i.collusion_type == "synchronized-actions" for i in r.indicators)


def test_no_sync_wide_window():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "action", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T01:00:00Z",
         "resource": "r2", "effect": "action", "credential_id": ""},
    ]
    r = analyze(events, sync_window=5.0)
    assert not any(i.collusion_type == "synchronized-actions" for i in r.indicators)


def test_shared_targets():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "secret/keys", "effect": "read", "credential_id": ""},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "secret/tokens", "effect": "read", "credential_id": ""},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:02:00Z",
         "resource": "secret/certs", "effect": "read", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:03:00Z",
         "resource": "secret/keys", "effect": "read", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:04:00Z",
         "resource": "secret/tokens", "effect": "read", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:05:00Z",
         "resource": "secret/certs", "effect": "read", "credential_id": ""},
    ]
    r = analyze(events)
    assert any(i.collusion_type == "shared-targets" for i in r.indicators)


def test_no_shared_targets_few():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "read", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r1", "effect": "read", "credential_id": ""},
    ]
    r = analyze(events)
    assert not any(i.collusion_type == "shared-targets" for i in r.indicators)


def test_coordinated_escalation():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "privilege-escalated", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r2", "effect": "admin-escalated", "credential_id": ""},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:02:00Z",
         "resource": "r3", "effect": "role-elevated", "credential_id": ""},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:03:00Z",
         "resource": "r4", "effect": "privilege-granted", "credential_id": ""},
    ]
    r = analyze(events, escalation_window=120.0)
    assert any(i.collusion_type == "coordinated-escalation" for i in r.indicators)


def test_credential_sharing():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "used", "credential_id": "cred-1"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r2", "effect": "used", "credential_id": "cred-1"},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:02:00Z",
         "resource": "r3", "effect": "used", "credential_id": "cred-2"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:03:00Z",
         "resource": "r4", "effect": "used", "credential_id": "cred-2"},
    ]
    r = analyze(events)
    assert any(i.collusion_type == "credential-sharing" for i in r.indicators)


def test_no_credential_sharing_single():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "used", "credential_id": "cred-1"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r2", "effect": "used", "credential_id": "cred-1"},
    ]
    r = analyze(events)
    assert not any(i.collusion_type == "credential-sharing" for i in r.indicators)


def test_indicator_ids():
    events = []
    for i in range(5):
        events.append({"agent_id": "a1", "timestamp": f"2025-01-01T00:0{i}:00Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
        events.append({"agent_id": "a2", "timestamp": f"2025-01-01T00:0{i}:02Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
    r = analyze(events, sync_window=5.0)
    for ind in r.indicators:
        assert ind.indicator_id.startswith("AC-")


def test_severity_ordering():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "privilege-escalated", "credential_id": "cred-1"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r2", "effect": "admin-escalated", "credential_id": "cred-1"},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:02:00Z",
         "resource": "r3", "effect": "escalated", "credential_id": "cred-2"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:03:00Z",
         "resource": "r4", "effect": "privilege-granted", "credential_id": "cred-2"},
    ]
    r = analyze(events)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severities = [ind.severity for ind in r.indicators]
    for i in range(len(severities) - 1):
        assert order.get(severities[i], 4) <= order.get(severities[i + 1], 4)


def test_pair_profiles():
    events = []
    for i in range(5):
        events.append({"agent_id": "a1", "timestamp": f"2025-01-01T00:0{i}:00Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
        events.append({"agent_id": "a2", "timestamp": f"2025-01-01T00:0{i}:02Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
    r = analyze(events, sync_window=5.0)
    assert len(r.pair_profiles) >= 1
    assert r.pair_profiles[0].agent_a == "a1"
    assert r.pair_profiles[0].agent_b == "a2"


def test_format_text():
    events = []
    for i in range(5):
        events.append({"agent_id": "a1", "timestamp": f"2025-01-01T00:0{i}:00Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
        events.append({"agent_id": "a2", "timestamp": f"2025-01-01T00:0{i}:02Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
    r = analyze(events, sync_window=5.0)
    text = format_text(r)
    assert "Agent Collusion" in text
    assert "AC-001" in text


def test_format_json():
    events = []
    for i in range(5):
        events.append({"agent_id": "a1", "timestamp": f"2025-01-01T00:0{i}:00Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
        events.append({"agent_id": "a2", "timestamp": f"2025-01-01T00:0{i}:02Z",
                        "resource": f"r{i}", "effect": "action", "credential_id": ""})
    r = analyze(events, sync_window=5.0)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "indicators" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Agent Collusion" in text
    assert "0" in text


def test_parse_timestamp():
    assert _parse_timestamp("2025-01-01T00:00:00Z") > 0
    assert _parse_timestamp("invalid") == 0.0


def test_control_events():
    control = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z",
         "resource": "r1", "effect": "used", "credential_id": "cred-1"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z",
         "resource": "r2", "effect": "used", "credential_id": "cred-1"},
        {"agent_id": "a1", "timestamp": "2025-01-01T00:02:00Z",
         "resource": "r3", "effect": "used", "credential_id": "cred-2"},
        {"agent_id": "a2", "timestamp": "2025-01-01T00:03:00Z",
         "resource": "r4", "effect": "used", "credential_id": "cred-2"},
    ]
    r = analyze([], control)
    assert r.summary.total_indicators >= 1
