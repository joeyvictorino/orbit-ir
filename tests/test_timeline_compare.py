"""Tests for orbit_ir.timeline_compare."""

import json
from pathlib import Path

from orbit_ir.timeline_compare import compare_timelines, format_compare_text, load_and_compare


def test_identical_timelines():
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    result = compare_timelines(events, list(events))
    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["changed_count"] == 0
    assert result["summary"]["unchanged_count"] == 2


def test_added_events():
    events_a = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    events_b = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    result = compare_timelines(events_a, events_b)
    assert result["summary"]["added_count"] == 1
    assert result["summary"]["removed_count"] == 0
    assert result["added"][0]["event_id"] == "e2"


def test_removed_events():
    events_a = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    events_b = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    result = compare_timelines(events_a, events_b)
    assert result["summary"]["removed_count"] == 1
    assert result["removed"][0]["event_id"] == "e2"


def test_changed_events():
    events_a = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z", "status": "ok"},
    ]
    events_b = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z", "status": "fail"},
    ]
    result = compare_timelines(events_a, events_b)
    assert result["summary"]["changed_count"] == 1
    assert result["changed"][0]["changed_fields"]["status"]["old"] == "ok"
    assert result["changed"][0]["changed_fields"]["status"]["new"] == "fail"


def test_agent_diff():
    events_a = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    events_b = [
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    result = compare_timelines(events_a, events_b)
    assert "a2" in result["agent_diff"]["added"]
    assert "a1" in result["agent_diff"]["removed"]


def test_empty_timelines():
    result = compare_timelines([], [])
    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["unchanged_count"] == 0


def test_key_fallback_without_event_id():
    events_a = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z", "source": "msg"},
    ]
    events_b = [
        {"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z", "source": "msg"},
    ]
    result = compare_timelines(events_a, events_b)
    assert result["summary"]["unchanged_count"] == 1


def test_text_output():
    events_a = [{"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"}]
    events_b = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    result = compare_timelines(events_a, events_b)
    text = format_compare_text(result)
    assert "Added:     1" in text
    assert "Timeline A: 1 events" in text


def test_load_and_compare(tmp_path):
    events_a = [{"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"}]
    events_b = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    fa = tmp_path / "timeline_a.jsonl"
    fb = tmp_path / "timeline_b.jsonl"
    fa.write_text("\n".join(json.dumps(e) for e in events_a))
    fb.write_text("\n".join(json.dumps(e) for e in events_b))
    result = load_and_compare(fa, fb)
    assert result["summary"]["added_count"] == 1


def test_time_ranges():
    events_a = [
        {"event_id": "e1", "timestamp": "2025-01-01T00:00:00Z"},
        {"event_id": "e2", "timestamp": "2025-01-01T02:00:00Z"},
    ]
    result = compare_timelines(events_a, [])
    assert result["time_range_a"]["start"] == "2025-01-01T00:00:00Z"
    assert result["time_range_a"]["end"] == "2025-01-01T02:00:00Z"
    assert result["time_range_b"]["start"] is None
