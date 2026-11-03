"""Tests for orbit_ir.frequency."""

import json
from pathlib import Path

from orbit_ir.frequency import build_frequency, format_frequency_text, load_and_build


def test_empty_events():
    result = build_frequency([])
    assert result["total_events"] == 0
    assert result["unique_agents"] == 0
    assert result["unique_types"] == 0


def test_agent_counts():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T10:00:00Z"},
        {"agent_id": "a1", "timestamp": "2025-01-01T11:00:00Z"},
        {"agent_id": "a2", "timestamp": "2025-01-01T12:00:00Z"},
    ]
    result = build_frequency(events)
    assert result["total_events"] == 3
    assert result["unique_agents"] == 2
    assert result["by_agent"][0] == ("a1", 2)
    assert result["by_agent"][1] == ("a2", 1)


def test_type_counts():
    events = [
        {"agent_id": "a1", "event_type": "message", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "event_type": "tool_call", "timestamp": "2025-01-01T01:00:00Z"},
        {"agent_id": "a1", "event_type": "message", "timestamp": "2025-01-01T02:00:00Z"},
    ]
    result = build_frequency(events)
    assert result["unique_types"] == 2
    assert result["by_type"][0] == ("message", 2)


def test_hourly_distribution():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T09:00:00Z"},
        {"agent_id": "a1", "timestamp": "2025-01-01T09:30:00Z"},
        {"agent_id": "a1", "timestamp": "2025-01-01T15:00:00Z"},
    ]
    result = build_frequency(events)
    assert result["hourly_distribution"][9] == 2
    assert result["hourly_distribution"][15] == 1
    assert result["hourly_distribution"][0] == 0


def test_agent_stats():
    events = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "timestamp": "2025-01-01T01:00:00Z"},
        {"agent_id": "a1", "timestamp": "2025-01-01T02:00:00Z"},
        {"agent_id": "a2", "timestamp": "2025-01-01T03:00:00Z"},
    ]
    result = build_frequency(events)
    stats = result["agent_stats"]
    assert stats["min"] == 1
    assert stats["max"] == 3
    assert stats["mean"] == 2.0


def test_text_output():
    events = [
        {"agent_id": "a1", "event_type": "msg", "timestamp": "2025-01-01T10:00:00Z"},
        {"agent_id": "a2", "event_type": "msg", "timestamp": "2025-01-01T11:00:00Z"},
    ]
    result = build_frequency(events)
    text = format_frequency_text(result)
    assert "Total events:  2" in text
    assert "Unique agents: 2" in text
    assert "Hourly distribution:" in text


def test_load_and_build(tmp_path):
    events = [
        {"agent_id": "a1", "event_type": "msg", "timestamp": "2025-01-01T10:00:00Z"},
        {"agent_id": "a2", "event_type": "tool", "timestamp": "2025-01-01T11:00:00Z"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events))
    result = load_and_build(f)
    assert result["total_events"] == 2


def test_detection_type_fallback():
    events = [{"agent_id": "a1", "detection_type": "lateral_movement", "timestamp": "2025-01-01T00:00:00Z"}]
    result = build_frequency(events)
    assert result["by_type"][0][0] == "lateral_movement"
