"""Tests for orbit_ir.detect module."""
import json
from pathlib import Path

from orbit_ir.detect import detect_anomalies, format_detect_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_detect_burst(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "timestamp": i * 100}
        for i in range(10)
    ]
    events.append({"event_id": "burst1", "agent_id": "a1", "timestamp": 901})
    events.append({"event_id": "burst2", "agent_id": "a1", "timestamp": 902})
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["burst"])
    assert result["detection_count"] > 0
    assert any(d["pattern"] == "burst" for d in result["detections"])


def test_detect_repeat(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(5)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["repeat"])
    assert result["detection_count"] > 0
    assert any(d["pattern"] == "repeat" for d in result["detections"])


def test_detect_escalation(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "severity": "low"},
        {"event_id": "e2", "agent_id": "a1", "severity": "medium"},
        {"event_id": "e3", "agent_id": "a1", "severity": "high"},
        {"event_id": "e4", "agent_id": "a1", "severity": "critical"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["escalation"])
    assert result["detection_count"] > 0
    assert any(d["pattern"] == "escalation" for d in result["detections"])


def test_detect_unusual_type(tmp_path):
    events = [
        {"event_id": f"e{i}", "type": "tool_call"} for i in range(20)
    ] + [{"event_id": "rare", "type": "exotic_event"}]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["unusual_type"])
    assert result["detection_count"] > 0
    assert any(d["pattern"] == "unusual_type" for d in result["detections"])


def test_detect_no_anomalies(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "response"},
        {"event_id": "e2", "agent_id": "a1", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["escalation"])
    assert result["detection_count"] == 0


def test_detect_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = detect_anomalies(inp)
    assert result["total_events"] == 0
    assert result["detection_count"] == 0


def test_detect_all_patterns(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "response", "timestamp": i * 100}
        for i in range(10)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp)
    assert "burst" in result["patterns_checked"]
    assert "repeat" in result["patterns_checked"]
    assert "escalation" in result["patterns_checked"]
    assert "unusual_type" in result["patterns_checked"]


def test_detect_sorted_by_severity(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "severity": "low"},
        {"event_id": "e2", "agent_id": "a1", "severity": "medium"},
        {"event_id": "e3", "agent_id": "a1", "severity": "high"},
        {"event_id": "e4", "agent_id": "a1", "severity": "critical"},
    ] + [
        {"event_id": f"e{i+5}", "agent_id": "a1", "type": "tool_call"}
        for i in range(5)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp)
    if result["detection_count"] >= 2:
        scores = [d["severity_score"] for d in result["detections"]]
        assert scores == sorted(scores, reverse=True)


def test_format_detect_text(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(5)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = detect_anomalies(inp, patterns=["repeat"])
    text = format_detect_text(result)
    assert "Anomaly Detection" in text
