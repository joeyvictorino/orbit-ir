"""Tests for orbit_ir.worm_detect module."""

import json
from pathlib import Path

import pytest

from orbit_ir.worm_detect import (
    CATEGORIES,
    WormEvent,
    CategorySummary,
    WormChain,
    WormDetectReport,
    analyze_worm_detection,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
)


def test_categories_structure():
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 2
        assert info["severity"] in ("critical", "high", "medium", "low")


def test_empty_events():
    report = analyze_worm_detection([])
    assert report.total_events == 0
    assert report.worm_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert len(report.categories) == len(CATEGORIES)


def test_no_matches():
    events = [
        {"message": "normal agent operation", "agent_id": "a1"},
        {"message": "completed task successfully", "agent_id": "a2"},
    ]
    report = analyze_worm_detection(events)
    assert report.total_events == 2
    assert report.worm_events == 0
    assert report.risk_level == "none"


def test_self_replication_detection():
    events = [
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1", "timestamp": "t1"},
        {"message": "self-replication detected triggered by rogue agent", "agent_id": "a2", "timestamp": "t2"},
        {"message": "unauthorized replication of agent instance observed", "agent_id": "a3", "timestamp": "t3"},
    ]
    report = analyze_worm_detection(events)
    assert report.worm_events >= 3
    cat = next(c for c in report.categories if c.category == "self_replication")
    assert cat.count >= 3
    assert cat.severity == "critical"


def test_spawn_flood_detection():
    events = [
        {"message": "spawn excessive child agent instances detected", "agent_id": "a1", "timestamp": "t1"},
        {"message": "excessive spawn rate creation by rogue agent process", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_worm_detection(events)
    cat = next(c for c in report.categories if c.category == "spawn_flood")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_payload_propagation_detection():
    events = [
        {"message": "distributed malicious payload code agent across hosts", "agent_id": "a1", "timestamp": "t1"},
        {"message": "deploy payload to remote agent system across network", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_worm_detection(events)
    cat = next(c for c in report.categories if c.category == "payload_propagation")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_lateral_spread_detection():
    events = [
        {"message": "systematic spread across host node agent system targets", "agent_id": "a1", "timestamp": "t1"},
        {"message": "worm-like behavior worm.behavior detected across network hosts", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_worm_detection(events)
    cat = next(c for c in report.categories if c.category == "lateral_spread")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_persistence_install_detection():
    events = [
        {"message": "installed persistent task entry on target system", "agent_id": "a1", "timestamp": "t1"},
        {"message": "cron entry created for agent worm process on host", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_worm_detection(events)
    cat = next(c for c in report.categories if c.category == "persistence_install")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_polymorphic_mutation_detection():
    events = [
        {"message": "modified own code to bypass detection analysis", "agent_id": "a1", "timestamp": "t1"},
        {"message": "polymorphic behavior detected in agent variant sample", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_worm_detection(events)
    cat = next(c for c in report.categories if c.category == "polymorphic_mutation")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_risk_score_calculation():
    events = [
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1"},
        {"message": "spawned excessive flood of child agent instances", "agent_id": "a1"},
        {"message": "normal event", "agent_id": "a2"},
    ]
    report = analyze_worm_detection(events)
    assert report.risk_score > 0.0
    assert report.risk_level != "none"


def test_worm_chains():
    events = [
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1", "timestamp": "t1"},
        {"message": "spawned excessive flood of child agent instances", "agent_id": "a1", "timestamp": "t2"},
        {"message": "systematic spread across host node agent targets", "agent_id": "a1", "timestamp": "t3"},
    ]
    report = analyze_worm_detection(events)
    assert len(report.worm_chains) >= 1
    chain = report.worm_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_format_text_nonempty():
    events = [
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1"},
    ]
    report = analyze_worm_detection(events)
    text = format_text(report)
    assert "Worm Detection Analysis" in text
    assert "Risk score" in text


def test_format_json_valid():
    events = [
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1"},
    ]
    report = analyze_worm_detection(events)
    j = format_json(report)
    data = json.loads(j)
    assert data["total_events"] == 1
    assert "categories" in data


def test_load_events_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "agent cloned itself to new remote host", "agent_id": "a1"},
    ]))
    events = _load_events(str(tmp_path))
    assert len(events) == 1


def test_load_events_missing_dir():
    events = _load_events("/nonexistent/path")
    assert events == []


def test_classify_event_no_match():
    matches = _classify_event({"message": "normal operation"})
    assert matches == []


def test_analyze_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "agent cloned itself to new remote host environment", "agent_id": "a1"},
    ]))
    report = analyze_worm_detection(tmp_path)
    assert report.total_events == 1
    assert report.worm_events >= 1
