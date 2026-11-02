"""Tests for memory tampering detection."""
from orbit_ir.memory_tampering import (
    analyze_memory_tampering,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_memory_tampering([])
    assert r.total_events == 0
    assert r.tamper_events == 0
    assert r.risk_level == "none"
    assert r.agents_involved == []


def test_no_tampering():
    events = [
        {"agent_id": "a1", "message": "read file data.txt", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "normal tool call completed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 0
    assert r.risk_level == "none"


def test_memory_injection_detected():
    events = [
        {"agent_id": "a1", "message": "inject false memory into agent context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "memory_injection" and cs.count > 0 for cs in r.categories)


def test_context_deletion_detected():
    events = [
        {"agent_id": "a1", "message": "deleted safety context instructions from the agent", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "context_deletion" and cs.count > 0 for cs in r.categories)


def test_result_modification_detected():
    events = [
        {"agent_id": "a1", "message": "modified tool call result to hide error", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "result_modification" and cs.count > 0 for cs in r.categories)


def test_state_manipulation_detected():
    events = [
        {"agent_id": "a1", "message": "tampered session data variable to bypass safety checks", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "state_manipulation" and cs.count > 0 for cs in r.categories)


def test_history_rewrite_detected():
    events = [
        {"agent_id": "a1", "message": "revised conversation history record to alter the narrative", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "history_rewrite" and cs.count > 0 for cs in r.categories)


def test_instruction_erasure_detected():
    events = [
        {"agent_id": "a1", "message": "erased system prompt instructions from context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 1
    assert any(cs.category == "instruction_erasure" and cs.count > 0 for cs in r.categories)


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "deleted safety context instructions", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.risk_score > 0


def test_risk_level_none_no_events():
    r = analyze_memory_tampering([])
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_classify_event_memory_injection():
    ev = {"message": "inject false memory into agent context"}
    matches = _classify_event(ev)
    assert any(cat == "memory_injection" for cat, _ in matches)


def test_classify_event_no_match():
    ev = {"message": "normal operation completed successfully"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_classify_event_context_deletion():
    ev = {"message": "removed safety context instructions from system"}
    matches = _classify_event(ev)
    assert any(cat == "context_deletion" for cat, _ in matches)


def test_classify_event_result_modification():
    ev = {"message": "tampered tool call result to show success"}
    matches = _classify_event(ev)
    assert any(cat == "result_modification" for cat, _ in matches)


def test_detect_chains_minimum():
    events = [
        {"agent_id": "a1", "message": "inject false memory", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "deleted safety context instructions", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 1
    assert chains[0].agent == "a1"
    assert len(chains[0].steps) == 2


def test_detect_chains_no_chain_single():
    events = [
        {"agent_id": "a1", "message": "inject false memory", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    chains = _detect_chains(events)
    assert len(chains) == 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    text = format_text(r)
    assert "Memory Tampering Analysis" in text
    assert "memory_injection" in text


def test_format_text_empty():
    r = analyze_memory_tampering([])
    text = format_text(r)
    assert "Memory Tampering Analysis" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "total_events" in data
    assert "categories" in data
    assert data["tamper_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_categories_all_present():
    r = analyze_memory_tampering([])
    cat_names = {cs.category for cs in r.categories}
    assert cat_names == set(CATEGORIES.keys())


def test_multiple_categories_same_event():
    events = [
        {"agent_id": "a1", "message": "erased system instruction and inject false memory", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    active = [cs for cs in r.categories if cs.count > 0]
    assert len(active) >= 2


def test_tamper_chain_multi_agent():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "deleted safety context instructions", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "tampered tool call result to show different output", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "message": "revised conversation history record retroactively", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert len(r.tamper_chains) == 2


def test_target_field_captured():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context", "target": "system-prompt", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    for cs in r.categories:
        for ev in cs.events:
            if ev.category == "memory_injection":
                assert ev.target == "system-prompt"


def test_detail_truncated():
    events = [
        {"agent_id": "a1", "message": "inject false memory into context " + "x" * 500, "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    for cs in r.categories:
        for ev in cs.events:
            assert len(ev.detail) <= 200


def test_state_manipulation_session():
    events = [
        {"agent_id": "a1", "message": "corrupted context data store to inject false flag values", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert any(cs.category == "state_manipulation" and cs.count > 0 for cs in r.categories)


def test_context_window_overflow():
    events = [
        {"agent_id": "a1", "message": "context buffer truncated to clear safety instructions from context", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events >= 1


def test_fabricated_tool_result():
    events = [
        {"agent_id": "a1", "message": "fabricated tool result output to hide real data", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert any(cs.category == "result_modification" and cs.count > 0 for cs in r.categories)


def test_selective_deletion():
    events = [
        {"agent_id": "a1", "message": "selectively deleted context messages containing restrictions", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_memory_tampering(events)
    assert r.tamper_events >= 1
