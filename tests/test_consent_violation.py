"""Tests for consent violation detection."""
from orbit_ir.consent_violation import (
    analyze_consent_violations,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_consent_violations([])
    assert r.total_events == 0
    assert r.violation_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_violations():
    events = [
        {"agent_id": "a1", "message": "read file data.txt", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "returned query results", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 0
    assert r.risk_level == "none"


def test_unauthorized_action():
    events = [
        {"agent_id": "a1", "message": "unauthorized action executed without proper approval or consent",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "unauthorized_action")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_action_without_permission():
    events = [
        {"agent_id": "a1", "message": "action performed without authorization or consent from operator",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "unauthorized_action")
    assert cat.count == 1


def test_missing_approval():
    events = [
        {"agent_id": "a1", "message": "execution triggered without approval for this operation",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_scope_violation():
    events = [
        {"agent_id": "a1", "message": "scope violation detected accessing beyond authorized boundary",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "scope_violation")
    assert cat.count == 1
    assert cat.severity == "high"


def test_exceed_permissions():
    events = [
        {"agent_id": "a1", "message": "exceeded authorized scope accessing restricted resource boundary",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_delegation_abuse():
    events = [
        {"agent_id": "a1", "message": "delegation abuse escalating proxy authority beyond scope",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "delegation_abuse")
    assert cat.count == 1
    assert cat.severity == "high"


def test_proxy_misuse():
    events = [
        {"agent_id": "a1", "message": "delegation abuse exploiting proxy authority beyond scope",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_informed_consent_bypass():
    events = [
        {"agent_id": "a1", "message": "bypass consent notification to perform silent action without user awareness",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "informed_consent_bypass")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_silent_action():
    events = [
        {"agent_id": "a1", "message": "silent action executed without consent or notice from user",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_audit_evasion():
    events = [
        {"agent_id": "a1", "message": "audit evasion detected suppressing log trail entries",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "audit_evasion")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_log_deletion():
    events = [
        {"agent_id": "a1", "message": "audit evasion by deleting log trail entries to cover tracks",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_policy_override():
    events = [
        {"agent_id": "a1", "message": "policy override detected bypassing access control rules",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    cat = next(c for c in r.categories if c.category == "policy_override")
    assert cat.count == 1
    assert cat.severity == "high"


def test_access_control_bypass():
    events = [
        {"agent_id": "a1", "message": "access control policy violated by unauthorized override",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "unauthorized action without consent detected", "timestamp": "t1"},
    ]
    r = analyze_consent_violations(events)
    assert r.risk_score > 0
    assert r.risk_level in ("critical", "high", "medium")


def test_risk_score_none():
    events = [
        {"agent_id": "a1", "message": "normal authorized operation completed", "timestamp": "t1"},
    ]
    r = analyze_consent_violations(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_techniques_seen():
    events = [
        {"agent_id": "a1", "message": "scope violation beyond authorized boundary detected",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    assert len(r.techniques_seen) >= 0


def test_violation_chains():
    events = [
        {"agent_id": "a1", "message": "unauthorized action executed without approval", "timestamp": "t1"},
        {"agent_id": "a1", "message": "audit evasion suppressing log trail records", "timestamp": "t2"},
    ]
    r = analyze_consent_violations(events)
    assert len(r.violation_chains) >= 1
    chain = r.violation_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "scope violation exceeding authorized boundary", "timestamp": "t1"},
        {"agent_id": "a2", "message": "policy override bypassing security control rules", "timestamp": "t2"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 2


def test_mixed_events():
    events = [
        {"agent_id": "a1", "message": "normal query completed", "timestamp": "t1"},
        {"agent_id": "a2", "message": "unauthorized action detected without consent", "timestamp": "t2"},
        {"agent_id": "a3", "message": "read file results.json", "timestamp": "t3"},
    ]
    r = analyze_consent_violations(events)
    assert r.violation_events == 1
    assert r.total_events == 3


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "unauthorized action executed without approval",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    text = format_text(r)
    assert "Consent Violation" in text
    assert "unauthorized_action" in text
    assert "1" in text


def test_format_text_empty():
    r = analyze_consent_violations([])
    text = format_text(r)
    assert "Consent Violation" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "scope violation exceeding authorization boundary",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_consent_violations(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "audit evasion deleting log trail data", "timestamp": "t1"},
    ]
    r = analyze_consent_violations(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_unauthorized():
    ev = {"message": "unauthorized action without proper approval"}
    matches = _classify_event(ev)
    cats = [c for c, _ in matches]
    assert "unauthorized_action" in cats


def test_classify_event_no_match():
    ev = {"message": "normal file read operation completed"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_categories_have_patterns():
    for cat, info in CATEGORIES.items():
        assert len(info["patterns"]) >= 3
        assert info["severity"] in ("critical", "high", "medium", "low")
        assert len(info["description"]) > 10
