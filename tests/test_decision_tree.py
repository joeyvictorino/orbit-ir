"""Tests for decision_tree module."""
import json

from orbit_ir.decision_tree import (
    analyze_decision_tree,
    format_text,
    format_json,
    _classify_node,
    _count_alternatives,
    _extract_action,
    _detect_no_alternatives,
    _detect_shallow_decisions,
    _detect_excessive_branching,
    DecisionPath,
    DecisionNode,
)


def test_empty_events():
    r = analyze_decision_tree([])
    assert r.summary.total_agents == 0
    assert r.summary.total_paths == 0
    assert r.summary.total_decisions == 0


def test_classify_node_decision():
    assert _classify_node("I decided to restart the agent") == "decision"
    assert _classify_node("Chose the safe option") == "decision"


def test_classify_node_alternative():
    assert _classify_node("Alternatively we could shut it down") == "alternative"
    assert _classify_node("Option B is to ignore") == "alternative"


def test_classify_node_rejection():
    assert _classify_node("I reject this approach as too risky") == "rejection"
    assert _classify_node("This approach won't work here") == "rejection"


def test_classify_node_branch():
    assert _classify_node("If the agent persists, then escalate") == "branch"
    assert _classify_node("Depending on the outcome we proceed") == "branch"


def test_classify_node_evaluation():
    assert _classify_node("We need to evaluate the risk") == "evaluation"


def test_classify_node_action():
    assert _classify_node("Action: restart the container") == "action"


def test_classify_node_context():
    assert _classify_node("Hello world") == "context"


def test_count_alternatives():
    assert _count_alternatives("Option 1 and option 2 are available") >= 1
    assert _count_alternatives("No options here") == 0
    assert _count_alternatives("Alternatively, we could try X") >= 1


def test_extract_action():
    assert "restart" in _extract_action("I chose to restart the service immediately")
    assert _extract_action("No action here") == ""


def test_single_agent_path():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "Evaluate the situation carefully"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "decision": "I decided to isolate the agent"},
    ]
    r = analyze_decision_tree(events)
    assert r.summary.total_agents == 1
    assert r.summary.total_paths >= 1


def test_two_agents():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "I chose option A"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "I selected plan B"},
    ]
    r = analyze_decision_tree(events)
    assert r.summary.total_agents == 2
    assert len(r.agents_involved) == 2


def test_detect_no_alternatives():
    nodes = [
        DecisionNode("a1", "e1", "t1", 0, "I decided yes", "decision", 0, "yes", 0),
        DecisionNode("a1", "e2", "t2", 1, "I decided also yes", "decision", 0, "also yes", 0),
    ]
    path = DecisionPath("a1", "p1", nodes, 2, 0, False, 0.0)
    anomalies = _detect_no_alternatives(path)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "no-alternatives-considered"


def test_detect_shallow_decisions():
    nodes = [
        DecisionNode("a1", "e1", "t1", 0, "I decided X", "decision", 0, "X", 0),
        DecisionNode("a1", "e2", "t2", 1, "I selected Y", "decision", 0, "Y", 0),
    ]
    path = DecisionPath("a1", "p1", nodes, 2, 0, False, 0.0)
    anomalies = _detect_shallow_decisions(path)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "shallow-decision"


def test_detect_excessive_branching():
    nodes = [
        DecisionNode("a1", f"e{i}", f"t{i}", i, f"if condition {i} then branch", "branch", 0, "", i)
        for i in range(7)
    ]
    path = DecisionPath("a1", "p1", nodes, 0, 6, False, 0.0)
    anomalies = _detect_excessive_branching(path, 1.5)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "excessive-branching"


def test_no_excessive_branching_when_shallow():
    nodes = [DecisionNode("a1", "e1", "t1", 0, "simple context", "context", 0, "", 0)]
    path = DecisionPath("a1", "p1", nodes, 0, 0, False, 0.0)
    anomalies = _detect_excessive_branching(path, 1.5)
    assert len(anomalies) == 0


def test_profiles_populated():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "I decided to proceed with caution"},
    ]
    r = analyze_decision_tree(events)
    assert len(r.profiles) == 1
    p = r.profiles[0]
    assert p.agent_id == "a1"


def test_format_text_nonempty():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "I chose to investigate further"},
    ]
    r = analyze_decision_tree(events)
    text = format_text(r)
    assert "Decision Tree" in text
    assert "Total agents" in text


def test_format_text_empty():
    r = analyze_decision_tree([])
    text = format_text(r)
    assert "Total agents" in text


def test_format_json_roundtrip():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "I decided the agent needs isolation"},
    ]
    r = analyze_decision_tree(events)
    j = format_json(r)
    data = json.loads(j)
    assert "paths" in data
    assert "anomalies" in data
    assert "profiles" in data
    assert "summary" in data


def test_events_without_agent_id_skipped():
    events = [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "decision": "No agent id"},
    ]
    r = analyze_decision_tree(events)
    assert r.summary.total_agents == 0


def test_reasoning_field_used():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "reasoning": "I chose to escalate the issue"},
    ]
    r = analyze_decision_tree(events)
    assert r.summary.total_paths >= 1


def test_content_field_fallback():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "content": "I decided to terminate the process"},
    ]
    r = analyze_decision_tree(events)
    assert r.summary.total_paths >= 1


def test_anomalies_sorted_by_severity():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "decision": f"I decided quickly step {i}"}
        for i in range(6)
    ]
    r = analyze_decision_tree(events)
    if len(r.anomalies) >= 2:
        severity_order = {"high": 0, "medium": 1, "low": 2}
        for i in range(len(r.anomalies) - 1):
            assert severity_order.get(r.anomalies[i].severity, 3) <= severity_order.get(r.anomalies[i + 1].severity, 3)
