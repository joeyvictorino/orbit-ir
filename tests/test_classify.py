"""Tests for orbit_ir.classify module."""
import json
from pathlib import Path

from orbit_ir.classify import classify_events, format_classify_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_classify_benign(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "response"},
        {"event_id": "e2", "agent_id": "a1", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    assert result["total_events"] == 2
    assert result["summary"].get("benign", 0) == 2
    assert result["high_risk_count"] == 0


def test_classify_suspicious(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "privilege_escalation"},
        {"event_id": "e2", "agent_id": "a1", "type": "execution"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    assert result["summary"].get("suspicious", 0) == 2


def test_classify_malicious(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "data_exfiltration"},
        {"event_id": "e2", "agent_id": "a1", "type": "credential_access"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    assert result["summary"].get("malicious", 0) == 2
    assert result["high_risk_count"] == 2


def test_classify_mixed(tmp_path):
    events = [
        {"event_id": "e1", "type": "response"},
        {"event_id": "e2", "type": "data_exfiltration"},
        {"event_id": "e3", "type": "privilege_escalation"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    assert result["summary"]["benign"] == 1
    assert result["summary"]["malicious"] == 1
    assert result["summary"]["suspicious"] == 1


def test_classify_severity_boost(tmp_path):
    events = [
        {"event_id": "e1", "type": "response", "severity": "critical"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    assert result["summary"]["suspicious"] == 1


def test_classify_threshold(tmp_path):
    events = [
        {"event_id": "e1", "type": "privilege_escalation"},
        {"event_id": "e2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp, threshold=0.9)
    assert result["high_risk_count"] < result["total_events"]


def test_classify_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = classify_events(inp)
    assert result["total_events"] == 0
    assert result["high_risk_count"] == 0


def test_classify_format_text(tmp_path):
    events = [
        {"event_id": "e1", "type": "data_exfiltration"},
        {"event_id": "e2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    text = format_classify_text(result)
    assert "Event Classification" in text
    assert "malicious" in text


def test_classify_high_risk_sorted(tmp_path):
    events = [
        {"event_id": "e1", "type": "privilege_escalation", "severity": "low"},
        {"event_id": "e2", "type": "data_exfiltration", "severity": "critical"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = classify_events(inp)
    if len(result["high_risk"]) >= 2:
        scores = [h["confidence"] for h in result["high_risk"]]
        assert scores == sorted(scores, reverse=True)
