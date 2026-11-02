"""Tests for orbit_ir.diff_agents module."""
import json
from pathlib import Path

from orbit_ir.diff_agents import diff_agents, format_diff_agents_text


def _make_evidence(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "messages.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_diff_agents_basic(tmp_path):
    events = [
        {"agent_id": "a1", "type": "message", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "type": "tool_call", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "type": "message", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    ev_dir = _make_evidence(tmp_path / "evidence", events)
    result = diff_agents(ev_dir, "a1", "a2")
    assert result["events_a"] == 2
    assert result["events_b"] == 1
    assert result["agent_a"] == "a1"
    assert result["agent_b"] == "a2"


def test_diff_agents_type_deltas(tmp_path):
    events = [
        {"agent_id": "a1", "type": "message", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "type": "message", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "type": "tool_call", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "type": "tool_call", "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a2", "type": "tool_call", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    ev_dir = _make_evidence(tmp_path / "evidence", events)
    result = diff_agents(ev_dir, "a1", "a2")

    td_by_type = {d["type"]: d for d in result["type_deltas"]}
    assert "message" in td_by_type
    assert td_by_type["message"]["a1"] == 2
    assert td_by_type["message"]["a2"] == 0


def test_diff_agents_only_types(tmp_path):
    events = [
        {"agent_id": "a1", "type": "message", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "type": "control", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    ev_dir = _make_evidence(tmp_path / "evidence", events)
    result = diff_agents(ev_dir, "a1", "a2")
    assert "message" in result["only_a_types"]
    assert "control" in result["only_b_types"]


def test_diff_agents_no_events(tmp_path):
    ev_dir = _make_evidence(tmp_path / "evidence", [])
    result = diff_agents(ev_dir, "a1", "a2")
    assert result["events_a"] == 0
    assert result["events_b"] == 0


def test_format_diff_agents_text(tmp_path):
    events = [
        {"agent_id": "a1", "type": "message", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "type": "tool_call", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    ev_dir = _make_evidence(tmp_path / "evidence", events)
    result = diff_agents(ev_dir, "a1", "a2")
    text = format_diff_agents_text(result)
    assert "Behavioral Delta" in text
    assert "a1" in text
    assert "a2" in text


def test_diff_agents_tools(tmp_path):
    events = [
        {"agent_id": "a1", "type": "tool_call", "tool_name": "read", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "type": "tool_call", "tool_name": "write", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "type": "tool_call", "tool_name": "exec", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    ev_dir = _make_evidence(tmp_path / "evidence", events)
    result = diff_agents(ev_dir, "a1", "a2")
    assert "read" in result["top_tools_a"]
    assert "exec" in result["top_tools_b"]
