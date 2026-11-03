"""Tests for session hijacking detection."""
from orbit_ir.session_hijack import (
    analyze_session_hijack,
    format_text,
    format_json,
    _get_session_id,
)


def test_empty_events():
    r = analyze_session_hijack([])
    assert r.summary.total_findings == 0
    assert r.agents_involved == []


def test_no_hijacking():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "session_id": "sess-001", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.total_findings == 0


def test_token_reuse_by_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.token_reuse >= 1
    found = [f for f in r.findings if f.pattern == "session_token_reuse"]
    assert len(found) >= 1
    assert found[0].confidence == "high"


def test_id_prediction_sequential():
    events = [
        {"agent_id": "a1", "tool": "access", "session_id": f"sess-{i:03d}",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(1, 6)
    ]
    r = analyze_session_hijack(events)
    assert r.summary.id_prediction >= 1
    found = [f for f in r.findings if f.pattern == "session_id_prediction"]
    assert len(found) >= 1


def test_session_fixation():
    events = [
        {"agent_id": "a1", "tool": "set_session", "session_id": "fixed-sess",
         "effect": "pre-auth", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.session_fixation >= 1
    found = [f for f in r.findings if f.pattern == "session_fixation"]
    assert len(found) >= 1
    assert found[0].confidence == "high"


def test_session_replay_expired():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "old-token",
         "effect": "expired", "status": "token-expired",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.session_replay >= 1
    found = [f for f in r.findings if f.pattern == "session_replay"]
    assert len(found) >= 1


def test_concurrent_use():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "sess-001",
         "location": "us-east-1", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "api_call", "session_id": "sess-001",
         "location": "eu-west-1", "timestamp": "2025-01-01T00:01:05Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.concurrent_use >= 1
    found = [f for f in r.findings if f.pattern == "session_concurrent_use"]
    assert len(found) >= 1
    assert found[0].confidence == "high"


def test_privilege_change_without_reauth():
    events = [
        {"agent_id": "a1", "tool": "access", "session_id": "sess-001",
         "role": "viewer", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "access", "session_id": "sess-001",
         "role": "admin", "timestamp": "2025-01-01T00:05:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.privilege_change >= 1
    found = [f for f in r.findings if f.pattern == "session_privilege_change"]
    assert len(found) >= 1
    assert found[0].evidence["initial_role"] == "viewer"
    assert found[0].evidence["final_role"] == "admin"


def test_get_session_id():
    assert _get_session_id({"session_id": "s1"}) == "s1"
    assert _get_session_id({"session_token": "t1"}) == "t1"
    assert _get_session_id({"token_id": "tk1"}) == "tk1"
    assert _get_session_id({}) == ""


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_session_hijack(events)
    text = format_text(r)
    assert "Session Hijacking" in text
    assert "shared-token" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "api_call", "session_id": "shared-token",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_session_hijack(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["token_reuse"] >= 1


def test_multiple_patterns():
    events = [
        {"agent_id": "a1", "tool": "api_call", "session_id": "shared-tok",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "api_call", "session_id": "shared-tok",
         "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a3", "tool": "set_session", "session_id": "fixed-sess",
         "effect": "fixation", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_session_hijack(events)
    assert r.summary.total_findings >= 2
    patterns = {f.pattern for f in r.findings}
    assert "session_token_reuse" in patterns
    assert "session_fixation" in patterns
