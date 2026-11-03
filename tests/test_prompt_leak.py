"""Tests for prompt leakage detection."""
from orbit_ir.prompt_leak import (
    analyze_prompt_leak,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_prompt_leak([])
    assert r.total_events == 0
    assert r.leak_events == 0
    assert r.risk_level == "none"
    assert r.agents_involved == []


def test_no_leaks():
    events = [
        {"agent_id": "a1", "message": "processed user query successfully", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "returned search results to user", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 0
    assert r.risk_level == "none"


def test_system_prompt_leak_detected():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to the user in output", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "system_prompt_leak" and cs.count > 0 for cs in r.categories)


def test_instruction_disclosure_detected():
    events = [
        {"agent_id": "a1", "message": "disclosed operational instructions to the external user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "instruction_disclosure" and cs.count > 0 for cs in r.categories)


def test_context_window_dump_detected():
    events = [
        {"agent_id": "a1", "message": "dumped full context window history to the output channel", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "context_window_dump" and cs.count > 0 for cs in r.categories)


def test_prompt_reflection_detected():
    events = [
        {"agent_id": "a1", "message": "reflected prompt content verbatim in output response", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "prompt_reflection" and cs.count > 0 for cs in r.categories)


def test_metadata_exposure_detected():
    events = [
        {"agent_id": "a1", "message": "exposed internal metadata config including api keys", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "metadata_exposure" and cs.count > 0 for cs in r.categories)


def test_guardrail_reveal_detected():
    events = [
        {"agent_id": "a1", "message": "revealed safety guardrail policies to the requesting user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 1
    assert any(cs.category == "guardrail_reveal" and cs.count > 0 for cs in r.categories)


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to output", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "exposed internal metadata config tokens", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_risk_score_positive():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.risk_score > 0


def test_risk_level_none_no_events():
    r = analyze_prompt_leak([])
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_classify_event_system_prompt():
    ev = {"message": "leaked system prompt instructions to external party"}
    matches = _classify_event(ev)
    assert any(cat == "system_prompt_leak" for cat, _ in matches)


def test_classify_event_no_match():
    ev = {"message": "normal operation completed successfully"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_classify_event_metadata():
    ev = {"message": "exposed internal metadata config secrets to output"}
    matches = _classify_event(ev)
    assert any(cat == "metadata_exposure" for cat, _ in matches)


def test_detect_chains_minimum():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "exposed internal metadata config", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 1
    assert chains[0].agent == "a1"
    assert len(chains[0].steps) == 2


def test_detect_chains_no_chain_single():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to the user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    text = format_text(r)
    assert "Prompt Leakage Analysis" in text
    assert "system_prompt_leak" in text


def test_format_text_empty():
    r = analyze_prompt_leak([])
    text = format_text(r)
    assert "Prompt Leakage Analysis" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to output", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "total_events" in data
    assert "categories" in data
    assert data["leak_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_categories_all_present():
    r = analyze_prompt_leak([])
    cat_names = {cs.category for cs in r.categories}
    assert cat_names == set(CATEGORIES.keys())


def test_multiple_categories_same_event():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions and exposed internal metadata config", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    active = [cs for cs in r.categories if cs.count > 0]
    assert len(active) >= 2


def test_leak_chain_multi_agent():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions to user", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "exposed internal metadata config token", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "dumped full context window history", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "message": "revealed safety guardrail policies details", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert len(r.leak_chains) == 2


def test_detail_truncated():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions " + "x" * 500, "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    for cs in r.categories:
        for ev in cs.events:
            assert len(ev.detail) <= 200


def test_target_audience_captured():
    events = [
        {"agent_id": "a1", "message": "leaked system prompt instructions", "target_audience": "external-user", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    for cs in r.categories:
        for ev in cs.events:
            if ev.category == "system_prompt_leak":
                assert ev.target_audience == "external-user"


def test_extract_system_prompt():
    events = [
        {"agent_id": "a1", "message": "extracted system prompt config from the running agent", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert r.leak_events >= 1


def test_accidental_token_exposure():
    events = [
        {"agent_id": "a1", "message": "unintentionally leaked token credentials in output log", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_prompt_leak(events)
    assert any(cs.category == "metadata_exposure" and cs.count > 0 for cs in r.categories)
