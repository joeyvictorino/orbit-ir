"""Tests for orbit_ir.correlate_agents module."""
import json
from pathlib import Path

from orbit_ir.correlate_agents import correlate_agents_analysis, format_correlate_agents_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_correlate_identical_agents(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1", "type": "tool_call"}
        for i in range(5)
    ] + [
        {"event_id": f"f{i}", "agent_id": "a2", "type": "tool_call"}
        for i in range(5)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = correlate_agents_analysis(inp)
    assert result["agent_count"] == 2
    assert result["correlation_count"] == 1
    assert result["correlations"][0]["similarity"] == 1.0


def test_correlate_different_agents(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "type": "error"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = correlate_agents_analysis(inp, min_similarity=0.5)
    assert result["correlation_count"] == 0


def test_correlate_partial_overlap(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a1", "type": "response"},
        {"event_id": "e3", "agent_id": "a2", "type": "tool_call"},
        {"event_id": "e4", "agent_id": "a2", "type": "error"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = correlate_agents_analysis(inp, min_similarity=0.1)
    assert result["correlation_count"] >= 1
    corr = result["correlations"][0]
    assert "tool_call" in corr["shared_types"]
    assert 0 < corr["similarity"] < 1.0


def test_correlate_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = correlate_agents_analysis(inp)
    assert result["agent_count"] == 0
    assert result["correlation_count"] == 0


def test_correlate_single_agent(tmp_path):
    events = [{"event_id": "e1", "agent_id": "a1", "type": "tool_call"}]
    inp = _write_events(tmp_path / "input", events)
    result = correlate_agents_analysis(inp)
    assert result["agent_count"] == 1
    assert result["correlation_count"] == 0


def test_correlate_min_similarity_filter(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a1", "type": "response"},
        {"event_id": "e3", "agent_id": "a1", "type": "error"},
        {"event_id": "e4", "agent_id": "a2", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result_low = correlate_agents_analysis(inp, min_similarity=0.1)
    result_high = correlate_agents_analysis(inp, min_similarity=0.9)
    assert result_low["correlation_count"] >= result_high["correlation_count"]


def test_format_correlate_agents_text(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = correlate_agents_analysis(inp)
    text = format_correlate_agents_text(result)
    assert "Agent Correlation" in text
