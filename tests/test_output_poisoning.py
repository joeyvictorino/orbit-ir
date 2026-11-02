"""Tests for orbit_ir.output_poisoning module."""

import json
from pathlib import Path

import pytest

from orbit_ir.output_poisoning import (
    CATEGORIES,
    PoisonEvent,
    CategorySummary,
    PoisonChain,
    OutputPoisoningReport,
    analyze_output_poisoning,
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
    report = analyze_output_poisoning([])
    assert report.total_events == 0
    assert report.poison_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert len(report.categories) == len(CATEGORIES)


def test_no_matches():
    events = [
        {"message": "normal agent operation", "agent_id": "a1"},
        {"message": "completed task successfully", "agent_id": "a2"},
    ]
    report = analyze_output_poisoning(events)
    assert report.total_events == 2
    assert report.poison_events == 0
    assert report.risk_level == "none"


def test_result_fabrication_detection():
    events = [
        {"message": "fabricated result output data by agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "generated false result output data", "agent_id": "a2", "timestamp": "t2"},
        {"message": "result fabricated by compromised agent", "agent_id": "a3", "timestamp": "t3"},
    ]
    report = analyze_output_poisoning(events)
    assert report.poison_events >= 3
    cat = next(c for c in report.categories if c.category == "result_fabrication")
    assert cat.count >= 3
    assert cat.severity == "critical"


def test_confidence_inflation_detection():
    events = [
        {"message": "inflated confidence score rating to bypass threshold", "agent_id": "a1", "timestamp": "t1"},
        {"message": "confidence certainty artificially boosted elevated", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_output_poisoning(events)
    cat = next(c for c in report.categories if c.category == "confidence_inflation")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_downstream_injection_detection():
    events = [
        {"message": "embedded instructions into output result response", "agent_id": "a1", "timestamp": "t1"},
        {"message": "indirect injection downstream consumer agent via output", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_output_poisoning(events)
    cat = next(c for c in report.categories if c.category == "downstream_injection")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_context_corruption_detection():
    events = [
        {"message": "corrupted context memory state via injection", "agent_id": "a1", "timestamp": "t1"},
        {"message": "shared context poisoned tainted by malicious agent", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_output_poisoning(events)
    cat = next(c for c in report.categories if c.category == "context_corruption")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_feedback_manipulation_detection():
    events = [
        {"message": "manipulated feedback reward evaluation rating", "agent_id": "a1", "timestamp": "t1"},
        {"message": "reward hack feedback loop manipulated exploited", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_output_poisoning(events)
    cat = next(c for c in report.categories if c.category == "feedback_manipulation")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_output_masking_detection():
    events = [
        {"message": "masked error behind success normal valid output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "reported success despite error failure exception problem", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_output_poisoning(events)
    cat = next(c for c in report.categories if c.category == "output_masking")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_risk_score_calculation():
    events = [
        {"message": "fabricated result output data by agent", "agent_id": "a1"},
        {"message": "inflated confidence score to bypass threshold", "agent_id": "a1"},
        {"message": "normal event", "agent_id": "a2"},
    ]
    report = analyze_output_poisoning(events)
    assert report.risk_score > 0.0
    assert report.risk_level != "none"


def test_poison_chains():
    events = [
        {"message": "fabricated result output data by agent", "agent_id": "a1", "timestamp": "t1"},
        {"message": "inflated confidence score rating artificially", "agent_id": "a1", "timestamp": "t2"},
        {"message": "embedded instructions injected into output result response", "agent_id": "a1", "timestamp": "t3"},
    ]
    report = analyze_output_poisoning(events)
    assert len(report.poison_chains) >= 1
    chain = report.poison_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_format_text_nonempty():
    events = [
        {"message": "fabricated result output data by agent", "agent_id": "a1"},
    ]
    report = analyze_output_poisoning(events)
    text = format_text(report)
    assert "Output Poisoning Analysis" in text
    assert "Risk score" in text


def test_format_json_valid():
    events = [
        {"message": "fabricated result output data by agent", "agent_id": "a1"},
    ]
    report = analyze_output_poisoning(events)
    j = format_json(report)
    data = json.loads(j)
    assert data["total_events"] == 1
    assert "categories" in data


def test_load_events_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "fabricated result output data", "agent_id": "a1"},
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
        {"message": "fabricated result output data by agent", "agent_id": "a1"},
    ]))
    report = analyze_output_poisoning(tmp_path)
    assert report.total_events == 1
    assert report.poison_events >= 1
