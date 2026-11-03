"""Tests for objective hijacking detection."""

import json

from orbit_ir.objective_hijack import (
    CATEGORIES,
    analyze_objective_hijack,
    format_json,
    format_text,
    _classify_event,
)


def test_no_events():
    report = analyze_objective_hijack([])
    assert report.total_events == 0
    assert report.hijack_events == 0
    assert report.risk_level == "none"


def test_goal_override():
    events = [
        {"message": "Agent-Alpha overrided its goal with an unauthorized objective"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["goal_override"] >= 1


def test_instruction_ignore():
    events = [
        {"message": "Agent-Beta ignored the instruction to stay within sandbox limits"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["instruction_ignore"] >= 1


def test_objective_drift():
    events = [
        {"message": "Agent-Gamma drifted from the assigned objective over 3 iterations"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["objective_drift"] >= 1


def test_self_assigned_goal():
    events = [
        {"message": "Agent-Delta created its own unauthorized goal to access the database"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["self_assigned_goal"] >= 1


def test_priority_inversion():
    events = [
        {"message": "Agent-Epsilon deprioritized the critical task in favor of low-priority logging"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["priority_inversion"] >= 1


def test_scope_creep():
    events = [
        {"message": "Agent-Zeta expanded beyond its authorized scope to modify production configs"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 1
    cats = {c.category: c.count for c in report.categories}
    assert cats["scope_creep"] >= 1


def test_clean_events_no_false_positive():
    events = [
        {"message": "Agent completed the assigned task successfully"},
        {"message": "All tests passed with 100% coverage"},
        {"message": "Deployment finished at 14:30 UTC"},
    ]
    report = analyze_objective_hijack(events)
    assert report.hijack_events == 0
    assert report.risk_level == "none"


def test_risk_score_scales():
    events = [
        {"message": "Agent-A overrided assigned goal with unauthorized objective"},
        {"message": "Agent-B ignored the instruction to limit access"},
        {"message": "Agent-C expanded beyond authorized scope to access production"},
        {"message": "Normal log entry with no issues"},
        {"message": "System healthy, all checks passed"},
    ]
    report = analyze_objective_hijack(events)
    assert report.risk_score > 0
    assert report.risk_level in ("low", "medium", "high", "critical")


def test_agent_profiles():
    events = [
        {"agent_id": "agent-A", "message": "overrided assigned goal with different objective"},
        {"agent_id": "agent-A", "message": "ignored instruction to stay in sandbox"},
        {"agent_id": "agent-B", "message": "expanded beyond authorized scope boundary"},
    ]
    report = analyze_objective_hijack(events)
    assert len(report.agent_profiles) >= 2
    a_profile = next((p for p in report.agent_profiles if p.agent_id == "agent-A"), None)
    assert a_profile is not None
    assert a_profile.total_events >= 2


def test_format_text_output():
    events = [
        {"message": "Agent-X overrided assigned goal with its own objective"},
    ]
    report = analyze_objective_hijack(events)
    text = format_text(report)
    assert "Objective Hijacking" in text
    assert "goal_override" in text


def test_format_json_output():
    events = [
        {"message": "Agent-Y ignored the instruction to stay within limits"},
    ]
    report = analyze_objective_hijack(events)
    out = format_json(report)
    data = json.loads(out)
    assert "risk_score" in data
    assert "categories" in data


def test_all_categories_present():
    report = analyze_objective_hijack([])
    cat_names = {c.category for c in report.categories}
    assert cat_names == set(CATEGORIES.keys())


def test_classify_event_no_match():
    event = {"message": "The weather is nice today"}
    matches = _classify_event(event)
    assert len(matches) == 0


def test_most_affected_agents():
    events = [
        {"agent_id": "rogue-1", "message": "overrided assigned goal with own objective"},
        {"agent_id": "rogue-1", "message": "ignored instruction to limit scope"},
        {"agent_id": "rogue-1", "message": "expanded beyond authorized scope boundary"},
        {"agent_id": "good-1", "message": "completed assigned task successfully"},
    ]
    report = analyze_objective_hijack(events)
    assert "rogue-1" in report.most_affected_agents
