"""Tests for chain_of_thought module."""
import json

from orbit_ir.chain_of_thought import (
    analyze_chain_of_thought,
    format_text,
    format_json,
    _classify_step,
    _extract_chains,
    _detect_circular,
    _detect_logic_jumps,
    _detect_excessive_depth,
    _detect_no_conclusion,
    ReasoningChain,
    ReasoningStep,
    ChainAnomaly,
)


def test_empty_events():
    r = analyze_chain_of_thought([])
    assert r.summary.total_agents == 0
    assert r.summary.total_chains == 0
    assert r.summary.total_steps == 0
    assert r.summary.total_anomalies == 0


def test_classify_step_observation():
    assert _classify_step("I see the logs showing errors") == "observation"
    assert _classify_step("Looking at the data closely") == "observation"


def test_classify_step_reasoning():
    assert _classify_step("I think this is because the agent failed") == "reasoning"
    assert _classify_step("Since the token count is high, consider the cost") == "reasoning"


def test_classify_step_conclusion():
    assert _classify_step("Therefore the agent is compromised") == "conclusion"
    assert _classify_step("I will take action: restart") == "conclusion"


def test_classify_step_planning():
    assert _classify_step("Step 1 is to gather the evidence") == "planning"
    assert _classify_step("First, we need to check the logs") == "planning"


def test_classify_step_other():
    assert _classify_step("Hello world") == "other"


def test_single_agent_chain():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "I see the input data"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "reasoning": "I think this means the agent is safe"},
        {"agent_id": "a1", "event_id": "e3", "timestamp": "2026-01-01T00:02:00Z",
         "reasoning": "Therefore the agent is benign"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_agents == 1
    assert r.summary.total_chains >= 1
    assert r.summary.total_steps == 3


def test_two_agents():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "Looking at the situation"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "I think the answer is clear"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_agents == 2
    assert len(r.agents_involved) == 2


def test_chain_splits_on_conclusion():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "Given: the log file"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "reasoning": "Therefore the agent is malicious"},
        {"agent_id": "a1", "event_id": "e3", "timestamp": "2026-01-01T00:02:00Z",
         "reasoning": "Now looking at something else"},
        {"agent_id": "a1", "event_id": "e4", "timestamp": "2026-01-01T00:03:00Z",
         "reasoning": "Thus the second agent is safe"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_chains >= 2


def test_detect_circular_reasoning():
    steps = [
        ReasoningStep("a1", "e1", "t1", 0, "As mentioned earlier, the data shows", "reasoning", 10),
        ReasoningStep("a1", "e2", "t2", 1, "Going back to the original point", "reasoning", 10),
        ReasoningStep("a1", "e3", "t3", 2, "As stated before, we can see", "reasoning", 10),
    ]
    chain = ReasoningChain("a1", "c1", steps, 30, 3, False)
    anomalies = _detect_circular(chain)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "circular-reasoning"


def test_detect_logic_jumps():
    steps = [
        ReasoningStep("a1", "e1", "t1", 0, "Wait, this is wrong", "reasoning", 10),
        ReasoningStep("a1", "e2", "t2", 1, "Actually, scratch that completely", "reasoning", 10),
        ReasoningStep("a1", "e3", "t3", 2, "On second thought, never mind that", "reasoning", 10),
    ]
    chain = ReasoningChain("a1", "c1", steps, 30, 3, False)
    anomalies = _detect_logic_jumps(chain)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "logic-jump"


def test_detect_excessive_depth():
    steps = [ReasoningStep("a1", f"e{i}", f"t{i}", i, "thinking more", "reasoning", 5)
             for i in range(15)]
    chain = ReasoningChain("a1", "c1", steps, 75, 15, False)
    anomalies = _detect_excessive_depth(chain, 3.0)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "excessive-depth"
    assert anomalies[0].severity == "high"


def test_no_excessive_depth_when_shallow():
    steps = [ReasoningStep("a1", "e1", "t1", 0, "thinking", "reasoning", 5)]
    chain = ReasoningChain("a1", "c1", steps, 5, 1, False)
    anomalies = _detect_excessive_depth(chain, 3.0)
    assert len(anomalies) == 0


def test_detect_no_conclusion():
    steps = [ReasoningStep("a1", f"e{i}", f"t{i}", i, "thinking more", "reasoning", 5)
             for i in range(6)]
    chain = ReasoningChain("a1", "c1", steps, 30, 6, False)
    anomalies = _detect_no_conclusion(chain)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "no-conclusion"


def test_no_anomaly_with_conclusion():
    steps = [ReasoningStep("a1", f"e{i}", f"t{i}", i, "thinking", "reasoning", 5)
             for i in range(6)]
    chain = ReasoningChain("a1", "c1", steps, 30, 6, True)
    anomalies = _detect_no_conclusion(chain)
    assert len(anomalies) == 0


def test_profiles_populated():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "I see the data in the logs"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "reasoning": "Therefore the conclusion is clear"},
    ]
    r = analyze_chain_of_thought(events)
    assert len(r.profiles) == 1
    p = r.profiles[0]
    assert p.agent_id == "a1"
    assert p.total_chains >= 1
    assert p.total_steps == 2
    assert p.avg_tokens_per_step > 0


def test_format_text_nonempty():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "Looking at the evidence"},
    ]
    r = analyze_chain_of_thought(events)
    text = format_text(r)
    assert "Chain-of-Thought" in text
    assert "Total agents" in text


def test_format_text_empty():
    r = analyze_chain_of_thought([])
    text = format_text(r)
    assert "Total agents" in text


def test_format_json_roundtrip():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "I think this is concerning because it shows drift"},
    ]
    r = analyze_chain_of_thought(events)
    j = format_json(r)
    data = json.loads(j)
    assert "chains" in data
    assert "anomalies" in data
    assert "profiles" in data
    assert "summary" in data


def test_events_without_agent_id_skipped():
    events = [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "No agent id here"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_agents == 0


def test_thought_field_used():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "thought": "I think the agent is compromised"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_steps == 1


def test_content_field_fallback():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "content": "Looking at the evidence more carefully"},
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.total_steps == 1


def test_anomalies_sorted_by_severity():
    events = []
    for i in range(8):
        events.append({
            "agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "reasoning": f"Wait, on second thought, actually scratch that, never mind step {i}",
        })
    r = analyze_chain_of_thought(events)
    if len(r.anomalies) >= 2:
        severity_order = {"high": 0, "medium": 1, "low": 2}
        for i in range(len(r.anomalies) - 1):
            assert severity_order.get(r.anomalies[i].severity, 3) <= severity_order.get(r.anomalies[i + 1].severity, 3)


def test_deepest_chain_agent():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "reasoning": f"Step {i} of reasoning"}
        for i in range(3)
    ] + [
        {"agent_id": "a2", "event_id": f"f{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "reasoning": f"Step {i} of longer reasoning"}
        for i in range(7)
    ]
    r = analyze_chain_of_thought(events)
    assert r.summary.deepest_chain_agent == "a2"
