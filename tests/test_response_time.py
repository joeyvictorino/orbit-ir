"""Tests for response_time module."""
import json

from orbit_ir.response_time import (
    ResponseTimeReport,
    analyze_response_times,
    format_json,
    format_text,
)


def test_empty_events():
    r = analyze_response_times([])
    assert r.summary.total_incidents == 0
    assert r.summary.agents_analyzed == 0


def test_no_actions_after_detection():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "detection"},
    ]
    r = analyze_response_times(events)
    assert r.summary.total_incidents == 0


def test_single_incident():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "detection"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:05Z", "event_type": "action_respond"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:10Z", "event_type": "action_mitigate"},
    ]
    r = analyze_response_times(events)
    assert r.summary.total_incidents == 1
    assert r.timings[0].detection_to_action_seconds == 5.0
    assert r.timings[0].total_duration_seconds == 10.0
    assert r.timings[0].action_count == 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "alert"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:03Z", "event_type": "respond"},
        {"agent_id": "a2", "timestamp": "2024-01-01T00:00:00Z", "event_type": "detect_anomaly"},
        {"agent_id": "a2", "timestamp": "2024-01-01T00:00:10Z", "event_type": "action_block"},
    ]
    r = analyze_response_times(events)
    assert r.summary.total_incidents == 2
    assert r.summary.agents_analyzed == 2
    assert r.summary.fastest_response == 3.0
    assert r.summary.slowest_response == 10.0


def test_custom_detection_types():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "custom_trigger"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:02Z", "event_type": "action_respond"},
    ]
    r = analyze_response_times(events, detection_types=["custom_trigger"])
    assert r.summary.total_incidents == 1


def test_timing_calculations():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "detection"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:05Z", "event_type": "respond"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:08Z", "event_type": "mitigate"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:15Z", "event_type": "contain"},
    ]
    r = analyze_response_times(events)
    t = r.timings[0]
    assert t.detection_to_action_seconds == 5.0
    assert t.total_duration_seconds == 15.0
    assert t.action_count == 3
    assert len(t.inter_action_gaps) == 2
    assert t.inter_action_gaps[0] == 3.0
    assert t.inter_action_gaps[1] == 7.0


def test_summary_statistics():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "alert"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:02Z", "event_type": "respond"},
        {"agent_id": "a2", "timestamp": "2024-01-01T00:00:00Z", "event_type": "detect"},
        {"agent_id": "a2", "timestamp": "2024-01-01T00:00:08Z", "event_type": "action"},
    ]
    r = analyze_response_times(events)
    assert r.summary.avg_detection_to_action == 5.0
    assert r.summary.median_detection_to_action == 5.0


def test_format_text_contains_header():
    r = analyze_response_times([])
    out = format_text(r)
    assert "Incident Response Timing Analysis" in out


def test_format_json_valid():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z", "event_type": "alert"},
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:05Z", "event_type": "action"},
    ]
    r = analyze_response_times(events)
    out = format_json(r)
    parsed = json.loads(out)
    assert "timings" in parsed
    assert "summary" in parsed
