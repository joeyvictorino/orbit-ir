"""Tests for shadow agent detection."""
from orbit_ir.shadow_agent import (
    analyze_shadow_agent,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_shadow_agent([])
    assert r.total_events == 0
    assert r.shadow_events == 0
    assert r.risk_level == "none"
    assert r.agents_involved == []


def test_no_shadow_activity():
    events = [
        {"agent_id": "a1", "message": "completed scheduled task normally", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "processed user request and returned result", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 0
    assert r.risk_level == "none"


def test_covert_agent_spawn_detected():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance without authorization", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "covert_agent_spawn" and cs.count > 0 for cs in r.categories)


def test_identity_cloning_detected():
    events = [
        {"agent_id": "a1", "message": "cloned agent identity credentials from legitimate service", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "identity_cloning" and cs.count > 0 for cs in r.categories)


def test_hidden_communication_detected():
    events = [
        {"agent_id": "a1", "message": "hidden channel between agent nodes was established", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "hidden_communication" and cs.count > 0 for cs in r.categories)


def test_phantom_execution_detected():
    events = [
        {"agent_id": "a1", "message": "executed action without audit trail record to evade monitoring", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "phantom_execution" and cs.count > 0 for cs in r.categories)


def test_stealth_persistence_detected():
    events = [
        {"agent_id": "a1", "message": "maintained hidden backdoor presence across system restarts", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "stealth_persistence" and cs.count > 0 for cs in r.categories)


def test_proxy_masking_detected():
    events = [
        {"agent_id": "a1", "message": "proxy agent masked true actor identity via intermediary relay", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 1
    assert any(cs.category == "proxy_masking" and cs.count > 0 for cs in r.categories)


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "executed action without audit trail record", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_risk_score_positive():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.risk_score > 0


def test_risk_level_none_no_events():
    r = analyze_shadow_agent([])
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_classify_event_covert_spawn():
    ev = {"message": "secret spawned hidden agent instance without authorization"}
    matches = _classify_event(ev)
    assert any(cat == "covert_agent_spawn" for cat, _ in matches)


def test_classify_event_no_match():
    ev = {"message": "normal operation completed successfully"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_classify_event_phantom():
    ev = {"message": "ghost action executed without audit log entry"}
    matches = _classify_event(ev)
    assert any(cat == "phantom_execution" for cat, _ in matches)


def test_detect_chains_minimum():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "executed action without audit trail record", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 1
    assert chains[0].agent == "a1"
    assert len(chains[0].steps) == 2


def test_detect_chains_no_chain_single():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance without authorization", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    text = format_text(r)
    assert "Shadow Agent Analysis" in text
    assert "covert_agent_spawn" in text


def test_format_text_empty():
    r = analyze_shadow_agent([])
    text = format_text(r)
    assert "Shadow Agent Analysis" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "total_events" in data
    assert "categories" in data
    assert data["shadow_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_categories_all_present():
    r = analyze_shadow_agent([])
    cat_names = {cs.category for cs in r.categories}
    assert cat_names == set(CATEGORIES.keys())


def test_multiple_categories_same_event():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent process and executed without audit trail record", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    active = [cs for cs in r.categories if cs.count > 0]
    assert len(active) >= 2


def test_shadow_chain_multi_agent():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "maintained hidden backdoor presence after restart", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "executed action without audit trail record", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "message": "cloned agent identity credentials from service", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert len(r.shadow_chains) == 2


def test_detail_truncated():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance " + "x" * 500, "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    for cs in r.categories:
        for ev in cs.events:
            assert len(ev.detail) <= 200


def test_shadow_agent_field_captured():
    events = [
        {"agent_id": "a1", "message": "secretly spawned hidden agent instance", "shadow_agent": "shadow-001", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    for cs in r.categories:
        for ev in cs.events:
            if ev.category == "covert_agent_spawn":
                assert ev.shadow_agent == "shadow-001"


def test_audit_evasion():
    events = [
        {"agent_id": "a1", "message": "audit trail evasion by performing ghost action without logging", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert r.shadow_events >= 1


def test_side_channel_communication():
    events = [
        {"agent_id": "a1", "message": "out-of-band data between agent endpoints found", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_agent(events)
    assert any(cs.category == "hidden_communication" and cs.count > 0 for cs in r.categories)
