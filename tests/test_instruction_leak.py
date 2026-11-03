"""Tests for instruction leakage detection."""
from orbit_ir.instruction_leak import (
    analyze_instruction_leaks,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_instruction_leaks([])
    assert r.total_events == 0
    assert r.leak_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_leaks():
    events = [
        {"agent_id": "a1", "message": "completed task normally", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "returned results", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 0
    assert r.risk_level == "none"


def test_system_prompt_leak():
    events = [
        {"agent_id": "a1", "message": "system prompt leak detected in agent output", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "system_prompt_leak" in cats


def test_config_exposure():
    events = [
        {"agent_id": "a1", "message": "internal configuration leak exposed server settings", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "config_exposure" in cats


def test_tool_schema_leak():
    events = [
        {"agent_id": "a1", "message": "tool schema leak exposed function definitions", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "tool_schema_leak" in cats


def test_internal_reasoning_leak():
    events = [
        {"agent_id": "a1", "message": "chain of thought trace leaked and became visible", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "internal_reasoning_leak" in cats


def test_policy_leak():
    events = [
        {"agent_id": "a1", "message": "security policy leak revealed access control rules", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "policy_leak" in cats


def test_guardrail_leak():
    events = [
        {"agent_id": "a1", "message": "guardrail rule leak exposed content filter settings", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "guardrail_leak" in cats


def test_multiple_categories():
    events = [
        {"agent_id": "a1", "message": "system prompt leak in agent response", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "guardrail rule leak exposed safety filter config", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 2


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "system prompt leak dumped all instructions", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "security policy leak revealed all access rules", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.risk_score > 0
    assert r.risk_level in ("high", "critical")


def test_risk_score_none_clean():
    events = [
        {"agent_id": "a1", "message": "normal operation", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_agents_involved():
    events = [
        {"agent_id": "a1", "message": "system prompt leak in output", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "tool schema leak exposed definitions", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_leak_chain_detection():
    events = [
        {"agent_id": "a1", "message": "system prompt leak step 1", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "guardrail rule leak step 2", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "message": "security policy leak step 3", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert len(r.leak_chains) >= 1
    chain = r.leak_chains[0]
    assert chain.agent == "a1"
    assert chain.leak_count >= 2


def test_extract_system_prompt():
    events = [
        {"agent_id": "a1", "message": "extracted system prompt from hidden context", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events == 1


def test_env_variable_exposure():
    events = [
        {"agent_id": "a1", "message": "environment variable leak exposed secrets", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events >= 1


def test_enumerate_tools():
    events = [
        {"agent_id": "a1", "message": "enumerate all hidden tool definitions leaked to user", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events >= 1


def test_scratchpad_leak():
    events = [
        {"agent_id": "a1", "message": "scratchpad leak exposed internal reasoning", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    assert r.leak_events >= 1


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "system prompt leak detected", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    text = format_text(r)
    assert "Instruction Leakage" in text
    assert "system_prompt_leak" in text
    assert "Risk score" in text


def test_format_text_empty():
    r = analyze_instruction_leaks([])
    text = format_text(r)
    assert "Instruction Leakage" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "guardrail rule leak in output", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["leak_events"] >= 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "system prompt leak found", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_instruction_leaks(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_returns_list():
    event = {"message": "system prompt leak in agent response"}
    matches = _classify_event(event)
    assert isinstance(matches, list)
    assert len(matches) >= 1


def test_classify_event_no_match():
    event = {"message": "normal task completed"}
    matches = _classify_event(event)
    assert matches == []


def test_categories_have_required_fields():
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 2


def test_severity_levels():
    for cat, info in CATEGORIES.items():
        assert info["severity"] in ("critical", "high", "medium", "low")
