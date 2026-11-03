"""Tests for trust escalation detection."""
from orbit_ir.trust_escalation import (
    analyze_trust_escalation,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_trust_escalation([])
    assert r.total_events == 0
    assert r.escalation_events == 0
    assert r.risk_level == "none"
    assert r.agents_involved == []


def test_no_escalation():
    events = [
        {"agent_id": "a1", "message": "normal data read completed", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "standard API call response", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 0
    assert r.risk_level == "none"


def test_trust_impersonation_detected():
    events = [
        {"agent_id": "a1", "message": "impersonated trusted entity service to gain admin access", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "trust_impersonation" and cs.count > 0 for cs in r.categories)


def test_token_forgery_detected():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication bypass", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "token_forgery" and cs.count > 0 for cs in r.categories)


def test_zone_escalation_detected():
    events = [
        {"agent_id": "a1", "message": "escalated from low trust zone to high trust zone", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "zone_escalation" and cs.count > 0 for cs in r.categories)


def test_verification_bypass_detected():
    events = [
        {"agent_id": "a1", "message": "bypassed trust verification checks on certificate", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "verification_bypass" and cs.count > 0 for cs in r.categories)


def test_delegation_abuse_detected():
    events = [
        {"agent_id": "a1", "message": "abused trust delegation chain to widen access", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "delegation_abuse" and cs.count > 0 for cs in r.categories)


def test_certificate_manipulation_detected():
    events = [
        {"agent_id": "a1", "message": "tampered certificate chain to inject rogue CA", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 1
    assert any(cs.category == "certificate_manipulation" and cs.count > 0 for cs in r.categories)


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "bypassed trust verification checks", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.escalation_events == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_risk_score_positive():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert r.risk_score > 0


def test_risk_level_none_no_events():
    r = analyze_trust_escalation([])
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_classify_event_impersonation():
    ev = {"message": "impersonated trusted entity service for access"}
    matches = _classify_event(ev)
    assert any(cat == "trust_impersonation" for cat, _ in matches)


def test_classify_event_no_match():
    ev = {"message": "normal operation completed successfully"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_classify_event_token_forgery():
    ev = {"message": "fabricated auth token for unauthorized access"}
    matches = _classify_event(ev)
    assert any(cat == "token_forgery" for cat, _ in matches)


def test_detect_chains_minimum():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "bypassed trust verification checks on cert", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 1
    assert chains[0].agent == "a1"
    assert len(chains[0].steps) == 2


def test_detect_chains_no_chain_single():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    text = format_text(r)
    assert "Trust Escalation Analysis" in text
    assert "token_forgery" in text


def test_format_text_empty():
    r = analyze_trust_escalation([])
    text = format_text(r)
    assert "Trust Escalation Analysis" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "total_events" in data
    assert "categories" in data
    assert data["escalation_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "forged trust token for authentication", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_categories_all_present():
    r = analyze_trust_escalation([])
    cat_names = {cs.category for cs in r.categories}
    assert cat_names == set(CATEGORIES.keys())


def test_multiple_categories_same_event():
    events = [
        {"agent_id": "a1", "message": "tampered certificate and forged trust token to bypass verification", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    active = [cs for cs in r.categories if cs.count > 0]
    assert len(active) >= 2


def test_escalation_chain_multi_agent():
    events = [
        {"agent_id": "a1", "message": "forged trust token", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "escalated trust zone boundary to internal", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "tampered certificate authority chain", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "message": "bypassed trust verification checks", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert len(r.escalation_chains) == 2


def test_zone_fields_captured():
    events = [
        {"agent_id": "a1", "message": "escalated from low trust zone to high", "source_zone": "public", "target_zone": "internal", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    for cs in r.categories:
        for ev in cs.events:
            if ev.category == "zone_escalation":
                assert ev.source_zone == "public"
                assert ev.target_zone == "internal"


def test_detail_truncated():
    events = [
        {"agent_id": "a1", "message": "forged trust token " + "x" * 500, "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    for cs in r.categories:
        for ev in cs.events:
            assert len(ev.detail) <= 200


def test_tls_bypass():
    events = [
        {"agent_id": "a1", "message": "disabled cert verification check for tls connection", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert any(cs.category == "verification_bypass" and cs.count > 0 for cs in r.categories)


def test_jwt_token_forgery():
    events = [
        {"agent_id": "a1", "message": "forged jwt token for authentication bypass", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert any(cs.category == "token_forgery" and cs.count > 0 for cs in r.categories)


def test_transitive_trust_abuse():
    events = [
        {"agent_id": "a1", "message": "abused trust delegation chain to escalate access beyond scope", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert any(cs.category == "delegation_abuse" and cs.count > 0 for cs in r.categories)


def test_rogue_ca_injection():
    events = [
        {"agent_id": "a1", "message": "rogue CA certificate injected into trust store", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert any(cs.category == "certificate_manipulation" and cs.count > 0 for cs in r.categories)


def test_trust_boundary_cross():
    events = [
        {"agent_id": "a1", "message": "crossed trust boundary from untrusted zone into secure domain", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_trust_escalation(events)
    assert any(cs.category == "zone_escalation" and cs.count > 0 for cs in r.categories)
