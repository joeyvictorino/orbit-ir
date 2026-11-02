"""Tests for credential replay attack detection."""
from orbit_ir.credential_replay import (
    analyze,
    format_text,
    format_json,
    _parse_timestamp,
    _detect_cross_agent_replay,
    _detect_post_revocation,
    _detect_temporal_replay,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_replays == 0
    assert r.agents_involved == []


def test_no_replay():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
    ]
    r = analyze(events)
    assert r.summary.total_replays == 0


def test_cross_agent_replay():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:30Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    assert r.summary.total_replays >= 1
    assert any(e.replay_type == "cross-agent" for e in r.events)


def test_cross_agent_critical_fast():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    cross = [e for e in r.events if e.replay_type == "cross-agent"]
    assert any(e.severity == "critical" for e in cross)


def test_post_revocation():
    control = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "revoked", "resource": "creds"},
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:05:00Z",
         "effect": "used", "resource": "r1"},
    ]
    r = analyze([], control)
    assert any(e.replay_type == "post-revocation" for e in r.events)
    assert any(e.severity == "critical" for e in r.events)


def test_no_post_revocation_before():
    control = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:05:00Z",
         "effect": "revoked", "resource": "creds"},
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
    ]
    r = analyze([], control)
    assert not any(e.replay_type == "post-revocation" for e in r.events)


def test_temporal_gap_replay():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T02:00:00Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events, gap_threshold=3600.0)
    assert any(e.replay_type == "temporal-gap" for e in r.events)


def test_no_temporal_gap_short():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:10:00Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events, gap_threshold=3600.0)
    assert not any(e.replay_type == "temporal-gap" for e in r.events)


def test_credential_profiles():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:30Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    assert len(r.credential_profiles) == 1
    assert r.credential_profiles[0].total_uses == 2
    assert sorted(r.credential_profiles[0].agents_using) == ["a1", "a2"]


def test_revoked_flag():
    control = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "credential-revoked", "resource": "creds"},
    ]
    r = analyze([], control)
    assert any(p.revoked for p in r.credential_profiles)


def test_event_ids_assigned():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    for e in r.events:
        assert e.event_id.startswith("CR-")


def test_severity_ordering():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severities = [e.severity for e in r.events]
    for i in range(len(severities) - 1):
        assert order.get(severities[i], 4) <= order.get(severities[i + 1], 4)


def test_parse_timestamp():
    assert _parse_timestamp("2025-01-01T00:00:00Z") > 0
    assert _parse_timestamp("invalid") == 0.0


def test_format_text():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Credential Replay" in text
    assert "CR-001" in text


def test_format_json():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "events" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Credential Replay" in text
    assert "0" in text


def test_confidence_range():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
    ]
    r = analyze(events)
    for e in r.events:
        assert 0.0 <= e.confidence <= 1.0


def test_multiple_credentials():
    events = [
        {"agent_id": "a1", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:00Z",
         "effect": "used", "resource": "r1"},
        {"agent_id": "a2", "credential_id": "cred-1", "timestamp": "2025-01-01T00:00:10Z",
         "effect": "used", "resource": "r2"},
        {"agent_id": "a1", "credential_id": "cred-2", "timestamp": "2025-01-01T00:01:00Z",
         "effect": "used", "resource": "r3"},
        {"agent_id": "a3", "credential_id": "cred-2", "timestamp": "2025-01-01T00:01:05Z",
         "effect": "used", "resource": "r4"},
    ]
    r = analyze(events)
    assert r.summary.credentials_replayed >= 2
