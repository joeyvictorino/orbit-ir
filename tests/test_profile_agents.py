"""Tests for agent behavior profiling."""

import json
import tempfile
from pathlib import Path

from orbit_ir.profile_agents import profile_agents, format_profile_text, _compute_risk, _build_profile


def _write_events(d: Path, events: list[dict], name: str = "events.jsonl") -> None:
    lines = [json.dumps(e) for e in events]
    (d / name).write_text("\n".join(lines))


def test_profile_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        result = profile_agents(d)
        assert result["total_agents"] == 0
        assert result["total_events"] == 0
        assert result["profiles"] == []


def test_profile_basic():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"agent_id": "a1", "tool_name": "bash", "action": "execute", "severity": "high", "timestamp": "2024-01-01T00:00:00Z"},
            {"agent_id": "a1", "tool_name": "read", "action": "read_file", "severity": "low", "timestamp": "2024-01-01T00:01:00Z"},
            {"agent_id": "a2", "tool_name": "bash", "action": "execute", "severity": "critical", "timestamp": "2024-01-01T00:00:30Z"},
        ]
        _write_events(Path(d), events)
        result = profile_agents(d)
        assert result["total_agents"] == 2
        assert result["total_events"] == 3
        assert len(result["profiles"]) == 2
        a1 = next(p for p in result["profiles"] if p["agent_id"] == "a1")
        assert a1["event_count"] == 2
        assert a1["unique_tools"] == 2


def test_profile_json_format():
    with tempfile.TemporaryDirectory() as d:
        events = [{"agent_id": "a1", "tool_name": "bash"}]
        _write_events(Path(d), events)
        result = profile_agents(d)
        text = json.dumps(result, sort_keys=True, indent=2)
        parsed = json.loads(text)
        assert parsed["total_agents"] == 1


def test_profile_text_format():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"agent_id": "a1", "tool_name": "bash", "action": "exec", "severity": "high"},
        ]
        _write_events(Path(d), events)
        result = profile_agents(d)
        text = format_profile_text(result)
        assert "a1" in text
        assert "bash" in text


def test_compute_risk():
    from collections import Counter
    sev = Counter({"critical": 2, "high": 3})
    tools = Counter({"a": 1})
    score = _compute_risk(sev, tools, 10)
    assert score == 35.0

    sev2 = Counter({"critical": 10, "high": 10})
    tools2 = Counter({f"t{i}": 1 for i in range(12)})
    score2 = _compute_risk(sev2, tools2, 200)
    assert score2 == 100.0


def test_profile_risk_score():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"agent_id": "a1", "severity": "critical"},
            {"agent_id": "a1", "severity": "critical"},
            {"agent_id": "a1", "severity": "high"},
        ]
        _write_events(Path(d), events)
        result = profile_agents(d)
        a1 = result["profiles"][0]
        assert a1["risk_score"] == 25.0


def test_profile_time_span():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z"},
            {"agent_id": "a1", "timestamp": "2024-01-01T12:00:00Z"},
        ]
        _write_events(Path(d), events)
        result = profile_agents(d)
        a1 = result["profiles"][0]
        assert "2024-01-01T00:00:00Z" in a1["time_span"]
        assert "2024-01-01T12:00:00Z" in a1["time_span"]
