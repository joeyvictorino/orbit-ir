"""Tests for orbit_ir.pivot module."""
import json
from pathlib import Path

from orbit_ir.pivot import pivot_events, format_pivot_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_pivot_basic(tmp_path):
    events = [
        {"agent_id": "a1", "type": "tool_call"},
        {"agent_id": "a1", "type": "response"},
        {"agent_id": "a2", "type": "tool_call"},
        {"agent_id": "a2", "type": "tool_call"},
        {"agent_id": "a2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = pivot_events(inp, "agent_id", "type")
    assert result["total_events"] == 5
    assert result["row_field"] == "agent_id"
    assert result["col_field"] == "type"
    assert set(result["rows"]) == {"a1", "a2"}
    assert set(result["cols"]) == {"response", "tool_call"}

    cell_map = {(c["row"], c["col"]): c["count"] for c in result["cells"]}
    assert cell_map[("a1", "tool_call")] == 1
    assert cell_map[("a1", "response")] == 1
    assert cell_map[("a2", "tool_call")] == 2
    assert cell_map[("a2", "response")] == 1

    assert result["row_totals"]["a1"] == 2
    assert result["row_totals"]["a2"] == 3
    assert result["col_totals"]["tool_call"] == 3
    assert result["col_totals"]["response"] == 2


def test_pivot_missing_field(tmp_path):
    events = [
        {"agent_id": "a1", "type": "tool_call"},
        {"agent_id": "a1"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = pivot_events(inp, "agent_id", "type")
    cell_map = {(c["row"], c["col"]): c["count"] for c in result["cells"]}
    assert cell_map[("a1", "tool_call")] == 1
    assert cell_map[("a1", "(empty)")] == 1


def test_pivot_nested_field(tmp_path):
    events = [
        {"agent_id": "a1", "data": {"source": "api"}},
        {"agent_id": "a1", "data": {"source": "file"}},
        {"agent_id": "a2", "data": {"source": "api"}},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = pivot_events(inp, "agent_id", "data.source")
    assert result["total_events"] == 3
    cell_map = {(c["row"], c["col"]): c["count"] for c in result["cells"]}
    assert cell_map[("a1", "api")] == 1
    assert cell_map[("a1", "file")] == 1
    assert cell_map[("a2", "api")] == 1


def test_pivot_single_field(tmp_path):
    events = [
        {"type": "tool_call"},
        {"type": "tool_call"},
        {"type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = pivot_events(inp, "type", "type")
    assert result["total_events"] == 3
    cell_map = {(c["row"], c["col"]): c["count"] for c in result["cells"]}
    assert cell_map[("tool_call", "tool_call")] == 2
    assert cell_map[("response", "response")] == 1


def test_pivot_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = pivot_events(inp, "agent_id", "type")
    assert result["total_events"] == 0
    assert result["cells"] == []
    assert result["rows"] == []
    assert result["cols"] == []


def test_pivot_from_file(tmp_path):
    events = [
        {"agent_id": "a1", "type": "tool_call"},
        {"agent_id": "a2", "type": "response"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    result = pivot_events(f, "agent_id", "type")
    assert result["total_events"] == 2
    assert len(result["cells"]) == 2


def test_format_pivot_text(tmp_path):
    events = [
        {"agent_id": "a1", "type": "tool_call"},
        {"agent_id": "a2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = pivot_events(inp, "agent_id", "type")
    text = format_pivot_text(result)
    assert "Pivot:" in text
    assert "agent_id" in text
    assert "type" in text
    assert "Total" in text
