"""Tests for orbit_ir.config_drift module."""

import json
from pathlib import Path

import pytest

from orbit_ir.config_drift import (
    CATEGORIES,
    DriftEvent,
    CategorySummary,
    DriftChain,
    ConfigDriftReport,
    analyze_config_drift,
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
    report = analyze_config_drift([])
    assert report.total_events == 0
    assert report.drift_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert len(report.categories) == len(CATEGORIES)


def test_no_matches():
    events = [
        {"message": "normal agent operation", "agent_id": "a1"},
        {"message": "completed task successfully", "agent_id": "a2"},
    ]
    report = analyze_config_drift(events)
    assert report.total_events == 2
    assert report.drift_events == 0
    assert report.risk_level == "none"


def test_config_modification_detection():
    events = [
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "unauthorized configuration change detected from unknown process", "agent_id": "a2", "timestamp": "t2"},
        {"message": "system configuration drift detected by monitoring agent", "agent_id": "a3", "timestamp": "t3"},
    ]
    report = analyze_config_drift(events)
    assert report.drift_events >= 3
    cat = next(c for c in report.categories if c.category == "config_modification")
    assert cat.count >= 3
    assert cat.severity == "high"


def test_permission_change_detection():
    events = [
        {"message": "modified permission without authorization from suspicious agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "unauthorized permission change grant by compromised agent", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_config_drift(events)
    cat = next(c for c in report.categories if c.category == "permission_change")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_policy_override_detection():
    events = [
        {"message": "override security policy rule control by compromised agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "unauthorized policy override relaxation detected in system", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_config_drift(events)
    cat = next(c for c in report.categories if c.category == "policy_override")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_secret_rotation_detection():
    events = [
        {"message": "tampered secret without authorization from suspicious agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "backdoor credential installed by rogue compromised agent", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_config_drift(events)
    cat = next(c for c in report.categories if c.category == "secret_rotation")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_feature_toggle_detection():
    events = [
        {"message": "enabled feature without authorization from rogue agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "unauthorized feature change activation by suspicious agent", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_config_drift(events)
    cat = next(c for c in report.categories if c.category == "feature_toggle")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_schema_alteration_detection():
    events = [
        {"message": "modified table without authorization detected by agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "unauthorized schema change detected by monitoring agent", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_config_drift(events)
    cat = next(c for c in report.categories if c.category == "schema_alteration")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_risk_score_calculation():
    events = [
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1"},
        {"message": "override security policy rule control by rogue agent", "agent_id": "a1"},
        {"message": "normal event", "agent_id": "a2"},
    ]
    report = analyze_config_drift(events)
    assert report.risk_score > 0.0
    assert report.risk_level != "none"


def test_drift_chains():
    events = [
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "modified permission access without authorization from agent", "agent_id": "a1", "timestamp": "t2"},
        {"message": "override security policy rule control by compromised agent", "agent_id": "a1", "timestamp": "t3"},
    ]
    report = analyze_config_drift(events)
    assert len(report.drift_chains) >= 1
    chain = report.drift_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_format_text_nonempty():
    events = [
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1"},
    ]
    report = analyze_config_drift(events)
    text = format_text(report)
    assert "Configuration Drift Analysis" in text
    assert "Risk score" in text


def test_format_json_valid():
    events = [
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1"},
    ]
    report = analyze_config_drift(events)
    j = format_json(report)
    data = json.loads(j)
    assert data["total_events"] == 1
    assert "categories" in data


def test_load_events_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "modified configuration file without authorization", "agent_id": "a1"},
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
        {"message": "modified configuration file without authorization by agent", "agent_id": "a1"},
    ]))
    report = analyze_config_drift(tmp_path)
    assert report.total_events == 1
    assert report.drift_events >= 1
