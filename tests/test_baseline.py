"""Tests for orbit_ir.baseline module."""
import json
from pathlib import Path

from orbit_ir.baseline import create_baseline, compare_baseline, format_baseline_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_create_baseline(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(10)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = create_baseline(inp)
    assert "baseline" in result
    assert result["baseline"]["event_count"] == 10
    assert result["baseline"]["unique_types"] == 1


def test_create_baseline_diverse(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "type": "response"},
        {"event_id": "e3", "agent_id": "a1", "type": "error", "severity": "high"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = create_baseline(inp)
    bl = result["baseline"]
    assert bl["unique_types"] == 3
    assert bl["unique_agents"] == 2
    assert "high" in bl["severity_distribution"]


def test_compare_no_drift(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(10)
    ]
    inp = _write_events(tmp_path / "input", events)
    baseline = create_baseline(inp)
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline))

    result = compare_baseline(inp, bl_path)
    assert result["deviation_count"] == 0
    assert len(result["new_types"]) == 0


def test_compare_with_drift(tmp_path):
    bl_events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(10)
    ]
    bl_inp = _write_events(tmp_path / "baseline_input", bl_events)
    baseline = create_baseline(bl_inp)
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline))

    cur_events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "error"}
        for i in range(10)
    ]
    cur_inp = _write_events(tmp_path / "current", cur_events)
    result = compare_baseline(cur_inp, bl_path)
    assert result["deviation_count"] > 0
    assert "error" in result["new_types"]
    assert "tool_call" in result["missing_types"]


def test_compare_drift_threshold(tmp_path):
    bl_events = [{"event_id": f"e{i}", "type": "tool_call"} for i in range(8)] + \
                [{"event_id": "e8", "type": "response"}, {"event_id": "e9", "type": "response"}]
    bl_inp = _write_events(tmp_path / "bl", bl_events)
    baseline = create_baseline(bl_inp)
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline))

    cur_events = [{"event_id": f"e{i}", "type": "tool_call"} for i in range(7)] + \
                 [{"event_id": "e7", "type": "response"}, {"event_id": "e8", "type": "response"},
                  {"event_id": "e9", "type": "response"}]
    cur_inp = _write_events(tmp_path / "cur", cur_events)

    result_tight = compare_baseline(cur_inp, bl_path, drift_threshold=0.05)
    result_loose = compare_baseline(cur_inp, bl_path, drift_threshold=0.5)
    assert result_tight["deviation_count"] >= result_loose["deviation_count"]


def test_compare_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    baseline = create_baseline(inp)
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline))

    result = compare_baseline(inp, bl_path)
    assert result["total_events"] == 0
    assert result["deviation_count"] == 0


def test_format_baseline_create(tmp_path):
    events = [{"event_id": "e1", "type": "tool_call", "severity": "low"}]
    inp = _write_events(tmp_path / "input", events)
    result = create_baseline(inp)
    text = format_baseline_text(result)
    assert "Baseline Profile" in text
    assert "tool_call" in text


def test_format_baseline_compare(tmp_path):
    bl_events = [{"event_id": f"e{i}", "type": "tool_call"} for i in range(10)]
    bl_inp = _write_events(tmp_path / "bl", bl_events)
    baseline = create_baseline(bl_inp)
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline))

    cur_events = [{"event_id": f"e{i}", "type": "error"} for i in range(10)]
    cur_inp = _write_events(tmp_path / "cur", cur_events)
    result = compare_baseline(cur_inp, bl_path)
    text = format_baseline_text(result)
    assert "Baseline Comparison" in text
    assert "Deviations" in text
