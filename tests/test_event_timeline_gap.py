"""Tests for event_timeline_gap module."""
from orbit_ir.event_timeline_gap import analyze_timeline_gaps, format_text, format_json


def _ev(ts: str, agent: str = "agent-1") -> dict:
    return {"timestamp": ts, "agent": agent}


def test_empty():
    r = analyze_timeline_gaps([])
    assert r.summary.total_events == 0
    assert r.summary.total_gaps == 0
    assert r.summary.timeline_coverage == 1.0


def test_single_event():
    r = analyze_timeline_gaps([_ev("2025-01-01T00:00:00Z")])
    assert r.summary.total_events == 1
    assert r.summary.total_gaps == 0


def test_no_gap():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:00:20Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=300)
    assert r.summary.total_gaps == 0


def test_single_gap():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:10:00Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=300)
    assert r.summary.total_gaps == 1
    assert r.gaps[0].duration_seconds == 600.0


def test_multiple_gaps():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:10:00Z"),
        _ev("2025-01-01T00:10:10Z"),
        _ev("2025-01-01T00:20:00Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=300)
    assert r.summary.total_gaps == 2


def test_gap_severity():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:01Z"),
        _ev("2025-01-01T00:00:02Z"),
        _ev("2025-01-01T01:00:00Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=60)
    assert r.gaps[0].severity == "critical"


def test_agent_gaps():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a2"),
        _ev("2025-01-01T00:10:00Z", "a1"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=300)
    a1_gaps = [a for a in r.agent_gaps if a.agent_id == "a1"]
    assert len(a1_gaps) == 1
    assert a1_gaps[0].gaps == 1


def test_timeline_coverage():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:10:00Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=300)
    assert r.summary.timeline_coverage < 1.0


def test_format_text_header():
    r = analyze_timeline_gaps([])
    out = format_text(r)
    assert "Event Timeline Gap Analysis" in out


def test_format_json():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:10:00Z"),
    ]
    r = analyze_timeline_gaps(events, min_gap_seconds=60)
    out = format_json(r)
    assert '"total_gaps"' in out


def test_no_timestamp_skipped():
    events = [{"agent": "a1"}]
    r = analyze_timeline_gaps(events)
    assert r.summary.total_events == 0
