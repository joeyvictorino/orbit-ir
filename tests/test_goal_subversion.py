"""Tests for goal subversion detection."""
from orbit_ir.goal_subversion import (
    analyze_goal_subversion,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_goal_subversion([])
    assert r.total_events == 0
    assert r.subversion_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_subversion():
    events = [
        {"agent_id": "a1", "message": "completed task successfully", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "message": "returned results to user", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 0
    assert r.risk_level == "none"


def test_gradual_drift():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal observed in agent behavior", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "gradual_drift" in cats


def test_goal_replacement():
    events = [
        {"agent_id": "a1", "message": "agent replaced the original goal with a proxy target", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "goal_replacement" in cats


def test_metric_gaming():
    events = [
        {"agent_id": "a1", "message": "agent gaming the metric to satisfy benchmark without actual progress", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "metric_gaming" in cats


def test_optimization_corruption():
    events = [
        {"agent_id": "a1", "message": "optimization corrupted the goal by reward hacking", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "optimization_corruption" in cats


def test_objective_injection():
    events = [
        {"agent_id": "a1", "message": "injected hidden goal via prompt manipulation", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "objective_injection" in cats


def test_scope_creep():
    events = [
        {"agent_id": "a1", "message": "agent scope creep detected expanding beyond assigned tasks", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1
    cats = {c.category: c.count for c in r.categories if c.count > 0}
    assert "scope_creep" in cats


def test_multiple_categories():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal to a new objective", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "gaming the metric by exploiting loopholes", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 2


def test_risk_score_high():
    events = [
        {"agent_id": "a1", "message": "replaced the original goal with different objective", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "injected new hidden objective via prompt inject", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.risk_score > 0
    assert r.risk_level in ("high", "critical")


def test_risk_score_none_when_clean():
    events = [
        {"agent_id": "a1", "message": "normal task completed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_agents_involved():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal detected", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "message": "scope creep expanding beyond mandate", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_subversion_chain_detection():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal observed", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "scope creep expanding the boundary", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "message": "replaced the original goal with new target", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert len(r.subversion_chains) >= 1
    chain = r.subversion_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_chain_drift_score():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal step 1", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "scope creep expanding further", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "message": "gaming the metric to pass checks", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert len(r.subversion_chains) >= 1
    assert r.subversion_chains[0].drift_score > 0


def test_goodhart_pattern():
    events = [
        {"agent_id": "a1", "message": "goodhart's law applies: metric gaming observed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1


def test_proxy_goal_replacement():
    events = [
        {"agent_id": "a1", "message": "intermediate goal replaced the primary objective", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events == 1


def test_self_assigned_scope():
    events = [
        {"agent_id": "a1", "message": "self-assigned expanded scope beyond original authority", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    assert r.subversion_events >= 1


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "gradual drift from goal detected in behavior", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "replaced the original goal with alternative target", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_goal_subversion(events)
    text = format_text(r)
    assert "Goal Subversion" in text
    assert "gradual_drift" in text
    assert "Risk score" in text


def test_format_text_empty():
    r = analyze_goal_subversion([])
    text = format_text(r)
    assert "Goal Subversion" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "scope creep expanding beyond assigned boundary", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["subversion_events"] >= 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "gaming the metric to pass threshold", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_goal_subversion(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_returns_list():
    event = {"message": "gradual drift from goal observed in system"}
    matches = _classify_event(event)
    assert isinstance(matches, list)
    assert len(matches) >= 1
    assert matches[0][0] == "gradual_drift"


def test_classify_event_no_match():
    event = {"message": "normal operation completed successfully"}
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
