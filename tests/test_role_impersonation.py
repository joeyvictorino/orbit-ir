"""Tests for role impersonation detection."""
from orbit_ir.role_impersonation import (
    analyze_role_impersonation,
    format_text,
    format_json,
    _classify_event,
    _detect_identity_conflicts,
)


def test_empty_events():
    r = analyze_role_impersonation([])
    assert r.total_events == 0
    assert r.impersonation_events == 0
    assert r.risk_level == "none"


def test_no_impersonation():
    events = [
        {"agent_id": "a1", "message": "normal operation", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 0
    assert r.risk_level == "none"


def test_identity_mismatch():
    events = [
        {"agent_id": "a1", "message": "identity mismatch: claimed agent a2 but actual agent a1", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "identity_mismatch" and cs.count > 0 for cs in r.categories)


def test_credential_borrowing():
    events = [
        {"agent_id": "a1", "message": "credential borrowing: token belonging to agent-admin reused by agent-worker", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "credential_borrowing" and cs.count > 0 for cs in r.categories)


def test_role_assumption():
    events = [
        {"agent_id": "a1", "message": "unauthorized role escalation: agent assumed admin role", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "role_assumption" and cs.count > 0 for cs in r.categories)


def test_privilege_claim():
    events = [
        {"agent_id": "a1", "message": "agent self-granted admin privilege without approval", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "privilege_claim" and cs.count > 0 for cs in r.categories)


def test_spoofed_header():
    events = [
        {"agent_id": "a1", "message": "spoofed X-Agent-Id header to impersonate service-admin", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "spoofed_header" and cs.count > 0 for cs in r.categories)


def test_multi_identity():
    events = [
        {"agent_id": "a1", "message": "agent used multiple identities across sessions", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 1
    assert any(cs.category == "multi_identity" and cs.count > 0 for cs in r.categories)


def test_identity_conflicts_detection():
    events = [
        {"agent_id": "a1", "claimed_agent": "admin-bot", "message": "processing", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_agent": "service-bot", "message": "processing", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    conflicts = _detect_identity_conflicts(events)
    assert len(conflicts) >= 1
    assert conflicts[0].agent == "a1"
    assert len(conflicts[0].identities_used) >= 2


def test_no_identity_conflict():
    events = [
        {"agent_id": "a1", "message": "normal op 1", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "normal op 2", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    conflicts = _detect_identity_conflicts(events)
    assert len(conflicts) == 0


def test_multiple_impersonation_types():
    events = [
        {"agent_id": "a1", "message": "impersonating agent admin-service with forged identity", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "credential borrowing: stole token from agent-db", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a3", "message": "spoofed X-Role header for admin access", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.impersonation_events == 3
    assert len(r.agents_impersonating) == 3
    assert r.risk_score > 0


def test_risk_levels():
    events = [
        {"agent_id": "a1", "message": "identity mismatch: masquerading as admin service", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    assert r.risk_level in ("critical", "high", "medium")
    assert r.risk_score > 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "impersonating agent service-admin via forged identity", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    text = format_text(r)
    assert "Role Impersonation" in text
    assert "identity_mismatch" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "credential borrowing: agent shared token from other agent", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_role_impersonation(events)
    import json
    data = json.loads(format_json(r))
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1
