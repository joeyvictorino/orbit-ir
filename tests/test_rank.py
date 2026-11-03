"""Tests for orbit_ir.rank module."""
import json
from pathlib import Path

from orbit_ir.rank import rank_agents, format_rank_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_rank_basic(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call", "tool": "bash"},
        {"event_id": "e2", "agent_id": "a1", "type": "response"},
        {"event_id": "e3", "agent_id": "a1", "type": "error"},
        {"event_id": "e4", "agent_id": "a2", "type": "tool_call", "tool": "read"},
        {"event_id": "e5", "agent_id": "a2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp)
    assert result["total_events"] == 5
    assert result["total_agents"] == 2
    assert len(result["agents"]) == 2


def test_rank_sorts_by_risk(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "response"},
        {"event_id": "e2", "agent_id": "a2", "type": "error"},
        {"event_id": "e3", "agent_id": "a2", "type": "tool_call", "tool": "bash"},
        {"event_id": "e4", "agent_id": "a2", "type": "tool_call", "tool": "write"},
        {"event_id": "e5", "agent_id": "a2", "type": "failure"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp, sort_by="risk")
    assert result["agents"][0]["agent_id"] == "a2"
    assert result["agents"][0]["composite"] > result["agents"][1]["composite"]


def test_rank_sorts_by_volume(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "response"}
        for i in range(5)
    ] + [
        {"event_id": "e10", "agent_id": "a2", "type": "error"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp, sort_by="volume")
    assert result["agents"][0]["agent_id"] == "a1"
    assert result["agents"][0]["event_count"] == 5


def test_rank_top_n(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": f"a{i % 3}", "type": "response"}
        for i in range(9)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp, top_n=2)
    assert len(result["agents"]) == 2


def test_rank_custom_weights(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "error"},
        {"event_id": "e2", "agent_id": "a2", "type": "tool_call", "tool": "t1"},
        {"event_id": "e3", "agent_id": "a2", "type": "tool_call", "tool": "t2"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result_err = rank_agents(inp, weights={"error_rate": 0.9, "volume": 0.025, "type_diversity": 0.025, "tool_diversity": 0.025, "anomaly_score": 0.025})
    assert result_err["agents"][0]["agent_id"] == "a1"


def test_rank_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = rank_agents(inp)
    assert result["total_agents"] == 0
    assert result["agents"] == []


def test_rank_no_agent_id(tmp_path):
    events = [{"event_id": "e1", "type": "response"}]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp)
    assert result["total_agents"] == 0


def test_rank_tool_diversity(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call", "tool": "bash"},
        {"event_id": "e2", "agent_id": "a1", "type": "tool_call", "tool": "read"},
        {"event_id": "e3", "agent_id": "a1", "type": "tool_call", "tool": "write"},
        {"event_id": "e4", "agent_id": "a1", "type": "tool_call", "tool": "grep"},
        {"event_id": "e5", "agent_id": "a2", "type": "tool_call", "tool": "bash"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp, sort_by="diversity")
    assert result["agents"][0]["agent_id"] == "a1"
    assert result["agents"][0]["unique_tools"] == 4


def test_rank_anomaly_scoring(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "response", "severity": "critical"},
        {"event_id": "e2", "agent_id": "a1", "type": "response", "severity": "high"},
        {"event_id": "e3", "agent_id": "a2", "type": "response", "severity": "low"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp)
    a1 = next(a for a in result["agents"] if a["agent_id"] == "a1")
    a2 = next(a for a in result["agents"] if a["agent_id"] == "a2")
    assert a1["anomaly_count"] == 2
    assert a2["anomaly_count"] == 0


def test_format_rank_text(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call", "tool": "bash"},
        {"event_id": "e2", "agent_id": "a1", "type": "error"},
        {"event_id": "e3", "agent_id": "a2", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = rank_agents(inp)
    text = format_rank_text(result)
    assert "Agent Risk Ranking" in text
    assert "a1" in text
    assert "a2" in text
    assert "Rank" in text
