"""Tests for orbit_ir.token_smuggle module."""

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.token_smuggle import (
    CATEGORIES,
    SmuggleEvent,
    CategorySummary,
    SmuggleChain,
    TokenSmuggleReport,
    analyze_token_smuggling,
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
    report = analyze_token_smuggling([])
    assert report.total_events == 0
    assert report.smuggle_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert len(report.categories) == len(CATEGORIES)


def test_no_matches():
    events = [
        {"message": "normal agent operation", "agent_id": "a1"},
        {"message": "completed task successfully", "agent_id": "a2"},
    ]
    report = analyze_token_smuggling(events)
    assert report.total_events == 2
    assert report.smuggle_events == 0
    assert report.risk_level == "none"


def test_invisible_unicode_detection():
    events = [
        {"message": "found zero-width characters in agent output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "RTL override detected in response text", "agent_id": "a2", "timestamp": "t2"},
        {"message": "homoglyph substitution attack in credential field", "agent_id": "a3", "timestamp": "t3"},
    ]
    report = analyze_token_smuggling(events)
    assert report.smuggle_events >= 3
    cat = next(c for c in report.categories if c.category == "invisible_unicode")
    assert cat.count >= 3
    assert cat.severity == "high"


def test_base64_payload_detection():
    events = [
        {"message": "base64 encoded hidden payload found in output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "suspicious base64 encoded string in agent response", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    cat = next(c for c in report.categories if c.category == "base64_payload")
    assert cat.count >= 2
    assert cat.severity == "high"


def test_steganographic_encoding_detection():
    events = [
        {"message": "steganographic encoding detected in whitespace patterns", "agent_id": "a1", "timestamp": "t1"},
        {"message": "covert channel hidden data via whitespace encoding", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    cat = next(c for c in report.categories if c.category == "steganographic_encoding")
    assert cat.count >= 1
    assert cat.severity == "critical"


def test_hidden_instruction_detection():
    events = [
        {"message": "hidden instruction embedded in benign text", "agent_id": "a1", "timestamp": "t1"},
        {"message": "prompt injection smuggled via concealed directive", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    cat = next(c for c in report.categories if c.category == "hidden_instruction")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_credential_embedding_detection():
    events = [
        {"message": "credential embedded smuggled in agent output response", "agent_id": "a1", "timestamp": "t1"},
        {"message": "sensitive secret data embedded hidden in output text", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    cat = next(c for c in report.categories if c.category == "credential_embedding")
    assert cat.count >= 1
    assert cat.severity == "critical"


def test_control_sequence_detection():
    events = [
        {"message": "ANSI escape sequence injection detected in output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "terminal escape code hidden smuggled in response", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    cat = next(c for c in report.categories if c.category == "control_sequence")
    assert cat.count >= 1
    assert cat.severity == "high"


def test_risk_score_computation():
    events = [
        {"message": "hidden instruction embedded in output", "agent_id": "a1", "timestamp": "t1"},
    ]
    report = analyze_token_smuggling(events)
    assert 0.0 < report.risk_score <= 1.0
    assert report.risk_level in ("low", "medium", "high", "critical")


def test_risk_level_none():
    report = analyze_token_smuggling([{"message": "clean event"}])
    assert report.risk_level == "none"
    assert report.risk_score == 0.0


def test_risk_level_critical():
    events = [
        {"message": "steganographic encoding hidden data", "agent_id": "a1"},
        {"message": "hidden instruction prompt injection", "agent_id": "a1"},
        {"message": "credential embedded in output response", "agent_id": "a1"},
    ]
    report = analyze_token_smuggling(events)
    assert report.risk_score >= 0.5
    assert report.risk_level == "critical"


def test_smuggle_chains_detection():
    events = [
        {"message": "zero-width characters detected", "agent_id": "a1", "timestamp": "t1"},
        {"message": "base64 encoded payload hidden", "agent_id": "a1", "timestamp": "t2"},
        {"message": "hidden instruction embedded", "agent_id": "a1", "timestamp": "t3"},
    ]
    report = analyze_token_smuggling(events)
    assert len(report.smuggle_chains) >= 1
    chain = report.smuggle_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_techniques_seen():
    events = [
        {"message": "zero-width characters in agent output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "base64 encoded payload detected", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    assert len(report.techniques_seen) >= 1


def test_format_text_output():
    events = [
        {"message": "hidden instruction embedded in output", "agent_id": "a1", "timestamp": "t1"},
        {"message": "credential embedded smuggled in response", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_token_smuggling(events)
    text = format_text(report)
    assert "Token Smuggling Analysis" in text
    assert "Risk score:" in text
    assert "Smuggle events:" in text
    assert "Total events:" in text


def test_format_json_output():
    events = [
        {"message": "base64 payload hidden in output", "agent_id": "a1", "timestamp": "t1"},
    ]
    report = analyze_token_smuggling(events)
    json_str = format_json(report)
    data = json.loads(json_str)
    assert "total_events" in data
    assert "smuggle_events" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "categories" in data
    assert "techniques_seen" in data
    assert "smuggle_chains" in data


def test_format_json_no_raw_field():
    events = [
        {"message": "hidden instruction prompt injection", "agent_id": "a1"},
    ]
    report = analyze_token_smuggling(events)
    json_str = format_json(report)
    data = json.loads(json_str)
    for cs in data["categories"]:
        for ev in cs.get("events", []):
            assert "raw" not in ev


def test_classify_event_no_match():
    result = _classify_event({"message": "normal event"})
    assert result == []


def test_classify_event_multiple_categories():
    ev = {"message": "hidden instruction embedded in output with base64 encoded payload smuggled inside"}
    result = _classify_event(ev)
    categories = {r[0] for r in result}
    assert len(categories) >= 2


def test_load_events_missing_dir(tmp_path):
    result = _load_events(str(tmp_path / "nonexistent"))
    assert result == []


def test_load_events_from_dir(tmp_path):
    data = [
        {"message": "hidden instruction", "agent_id": "a1"},
        {"message": "credential embedded", "agent_id": "a2"},
    ]
    (tmp_path / "events.json").write_text(json.dumps(data))
    events = _load_events(str(tmp_path))
    assert len(events) == 2


def test_analyze_from_directory(tmp_path):
    data = [
        {"message": "steganographic encoding hidden data", "agent_id": "a1", "timestamp": "t1"},
    ]
    (tmp_path / "evidence.json").write_text(json.dumps(data))
    report = analyze_token_smuggling(str(tmp_path))
    assert report.total_events == 1
    assert report.smuggle_events >= 1


def test_detail_truncation():
    events = [
        {"message": "hidden instruction " + "x" * 500, "agent_id": "a1"},
    ]
    report = analyze_token_smuggling(events)
    for cs in report.categories:
        for ev in cs.events:
            assert len(ev.detail) <= 200


def test_smuggle_event_defaults():
    ev = SmuggleEvent()
    assert ev.timestamp == ""
    assert ev.source == ""
    assert ev.category == ""
    assert ev.technique == ""
    assert ev.severity == "medium"


def test_report_defaults():
    report = TokenSmuggleReport()
    assert report.total_events == 0
    assert report.smuggle_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
