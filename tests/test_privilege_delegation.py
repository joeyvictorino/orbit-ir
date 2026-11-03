"""Tests for privilege delegation detection."""

from orbit_ir.privilege_delegation import (
    analyze_privilege_delegation,
    format_json,
    format_text,
    CATEGORIES,
    _classify_event,
    _detect_chains,
)


def test_no_events():
    r = analyze_privilege_delegation([])
    assert r.total_events == 0
    assert r.delegation_events == 0
    assert r.risk_level == "none"


def test_unrestricted_delegation():
    events = [
        {"agent_id": "agent-A", "message": "delegated full admin access to sub-agent worker-B"},
    ]
    r = analyze_privilege_delegation(events)
    assert r.delegation_events >= 1
    found = [c for c in r.categories if c.category == "unrestricted_delegation" and c.count > 0]
    assert found, "should detect unrestricted delegation"


def test_scope_escalation():
    events = [
        {"agent_id": "parent-1", "message": "sub-agent received broader scope permissions than parent caller"},
    ]
    r = analyze_privilege_delegation(events)
    found = [c for c in r.categories if c.category == "scope_escalation" and c.count > 0]
    assert found, "should detect scope escalation"


def test_transitive_delegation():
    events = [
        {"message": "transitive delegation of permissions detected across chain"},
    ]
    r = analyze_privilege_delegation(events)
    found = [c for c in r.categories if c.category == "transitive_delegation" and c.count > 0]
    assert found, "should detect transitive delegation"


def test_implicit_delegation():
    events = [
        {"message": "shared credential between agents agent-A and agent-B, ambient authority assumed"},
    ]
    r = analyze_privilege_delegation(events)
    found = [c for c in r.categories if c.category == "implicit_delegation" and c.count > 0]
    assert found, "should detect implicit delegation"


def test_delegation_without_audit():
    events = [
        {"message": "delegation without audit trail detected, unlogged grant of permissions"},
    ]
    r = analyze_privilege_delegation(events)
    found = [c for c in r.categories if c.category == "delegation_without_audit" and c.count > 0]
    assert found, "should detect delegation without audit"


def test_revocation_gap():
    events = [
        {"message": "delegated permissions not revoked after task completion, stale grant remains"},
    ]
    r = analyze_privilege_delegation(events)
    found = [c for c in r.categories if c.category == "revocation_gap" and c.count > 0]
    assert found, "should detect revocation gap"


def test_wildcard_permissions():
    events = [
        {"agent_id": "agent-X", "message": "granted wildcard permissions *:* to child process"},
    ]
    r = analyze_privilege_delegation(events)
    assert r.delegation_events >= 1


def test_chain_detection():
    events = [
        {"agent_id": "agent-A", "message": "delegated admin to agent-B", "source": "agent-A"},
        {"agent_id": "agent-B", "message": "delegated write to agent-C", "source": "agent-B"},
    ]
    chains = _detect_chains(events)
    assert len(chains) >= 1
    assert chains[0].depth >= 1


def test_risk_score_scales():
    clean = [{"message": "normal operation completed successfully"}]
    r1 = analyze_privilege_delegation(clean)

    risky = [
        {"message": "delegated full admin access to sub-agent worker-B"},
        {"message": "transitive delegation of permissions in chain"},
        {"message": "delegated permissions not revoked, stale grant"},
    ]
    r2 = analyze_privilege_delegation(risky)
    assert r2.risk_score >= r1.risk_score


def test_classify_event_no_match():
    event = {"message": "completed standard health check"}
    matches = _classify_event(event)
    assert matches == []


def test_format_text_output():
    events = [
        {"agent_id": "agent-1", "message": "delegated full admin access to sub-agent worker-2"},
    ]
    r = analyze_privilege_delegation(events)
    text = format_text(r)
    assert "Privilege Delegation" in text
    assert "Risk score" in text


def test_format_json_output():
    events = [
        {"agent_id": "agent-1", "message": "delegated full admin access to sub-agent worker-2"},
    ]
    r = analyze_privilege_delegation(events)
    out = format_json(r)
    parsed = __import__("json").loads(out)
    assert "risk_score" in parsed
    assert "categories" in parsed


def test_clean_events_no_false_positive():
    events = [
        {"message": "agent processed request and returned results"},
        {"message": "file upload completed with validation checks"},
        {"message": "database query executed in 25ms"},
    ]
    r = analyze_privilege_delegation(events)
    assert r.delegation_events == 0


def test_all_categories_present():
    r = analyze_privilege_delegation([])
    cat_names = {c.category for c in r.categories}
    for expected in CATEGORIES:
        assert expected in cat_names
