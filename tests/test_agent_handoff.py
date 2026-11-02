"""Tests for agent_handoff module."""
from orbit_ir.agent_handoff import analyze_handoffs, format_text, format_json


def _ev(ts: str, agent: str = "agent-1") -> dict:
    return {"timestamp": ts, "agent": agent}


def test_empty():
    r = analyze_handoffs([])
    assert r.summary.total_handoffs == 0
    assert r.summary.agents_involved == 0


def test_single_agent_no_handoff():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a1"),
    ]
    r = analyze_handoffs(events)
    assert r.summary.total_handoffs == 0


def test_simple_handoff():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a2"),
    ]
    r = analyze_handoffs(events)
    assert r.summary.total_handoffs == 1
    assert r.handoffs[0].from_agent == "a1"
    assert r.handoffs[0].to_agent == "a2"


def test_handoff_latency():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:10Z", "a2"),
    ]
    r = analyze_handoffs(events)
    assert r.handoffs[0].latency_seconds == 10.0


def test_multiple_handoffs():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a2"),
        _ev("2025-01-01T00:00:10Z", "a3"),
    ]
    r = analyze_handoffs(events)
    assert r.summary.total_handoffs == 2
    assert r.summary.agents_involved == 3


def test_chain_detection():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:02Z", "a2"),
        _ev("2025-01-01T00:00:04Z", "a3"),
    ]
    r = analyze_handoffs(events, handoff_gap_seconds=5)
    assert len(r.chains) >= 1
    assert r.chains[0].depth == 3


def test_busiest_pair():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:02Z", "a2"),
        _ev("2025-01-01T00:00:04Z", "a1"),
        _ev("2025-01-01T00:00:06Z", "a2"),
    ]
    r = analyze_handoffs(events)
    assert "a1" in r.summary.busiest_pair
    assert "a2" in r.summary.busiest_pair


def test_agent_profiles():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a2"),
        _ev("2025-01-01T00:00:10Z", "a1"),
    ]
    r = analyze_handoffs(events)
    a1_profile = next(p for p in r.profiles if p.agent_id == "a1")
    assert a1_profile.handoffs_out >= 1


def test_dropped_handoff():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:10:00Z", "a2"),
    ]
    r = analyze_handoffs(events, handoff_gap_seconds=5)
    assert r.summary.dropped_handoffs >= 1


def test_format_text_header():
    r = analyze_handoffs([])
    out = format_text(r)
    assert "Agent Handoff Analysis" in out


def test_format_json():
    events = [
        _ev("2025-01-01T00:00:00Z", "a1"),
        _ev("2025-01-01T00:00:05Z", "a2"),
    ]
    r = analyze_handoffs(events)
    out = format_json(r)
    assert '"total_handoffs"' in out
