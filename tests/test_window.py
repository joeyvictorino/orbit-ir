"""Tests for orbit_ir.window module."""
import json
from pathlib import Path

from orbit_ir.window import window_analysis, format_window_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_window_basic(tmp_path):
    events = [{"event_id": f"e{i}", "timestamp": i * 10} for i in range(20)]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=5, step=5)
    assert result["total_events"] == 20
    assert len(result["windows"]) == 4
    assert result["windows"][0]["event_count"] == 5
    assert result["windows"][0]["value"] == 5


def test_window_overlap(tmp_path):
    events = [{"event_id": f"e{i}", "timestamp": i} for i in range(10)]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=6, step=3)
    assert len(result["windows"]) == 4


def test_window_agents_metric(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": 1},
        {"event_id": "e2", "agent_id": "a1", "timestamp": 2},
        {"event_id": "e3", "agent_id": "a2", "timestamp": 3},
        {"event_id": "e4", "agent_id": "a3", "timestamp": 4},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=4, step=4, metric="agents")
    assert result["windows"][0]["value"] == 3


def test_window_types_metric(tmp_path):
    events = [
        {"event_id": "e1", "type": "tool_call", "timestamp": 1},
        {"event_id": "e2", "type": "response", "timestamp": 2},
        {"event_id": "e3", "type": "tool_call", "timestamp": 3},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=3, step=3, metric="types")
    assert result["windows"][0]["value"] == 2


def test_window_errors_metric(tmp_path):
    events = [
        {"event_id": "e1", "type": "error", "timestamp": 1},
        {"event_id": "e2", "type": "response", "timestamp": 2},
        {"event_id": "e3", "type": "failure", "timestamp": 3},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=3, step=3, metric="errors")
    assert result["windows"][0]["value"] == 2


def test_window_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = window_analysis(inp)
    assert result["total_events"] == 0
    assert result["windows"] == []


def test_window_default_step(tmp_path):
    events = [{"event_id": f"e{i}", "timestamp": i} for i in range(10)]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=6)
    assert result["step"] == 3


def test_format_window_text(tmp_path):
    events = [{"event_id": f"e{i}", "timestamp": i * 10} for i in range(10)]
    inp = _write_events(tmp_path / "input", events)
    result = window_analysis(inp, window_size=5)
    text = format_window_text(result)
    assert "Sliding Window" in text
    assert "Win" in text
