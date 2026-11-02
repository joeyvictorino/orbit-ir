"""Tests for event_cluster module."""
from orbit_ir.event_cluster import analyze_event_clusters, format_text, format_json


def _ev(ts: str, agent: str = "agent-1", tool: str = "read_file") -> dict:
    return {"timestamp": ts, "agent": agent, "tool": tool}


def test_empty():
    r = analyze_event_clusters([])
    assert r.summary.total_events == 0
    assert r.summary.total_clusters == 0
    assert r.summary.campaigns == 0


def test_single_cluster():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:00:20Z"),
    ]
    r = analyze_event_clusters(events)
    assert r.summary.total_clusters == 1
    assert r.summary.total_events == 3
    assert r.clusters[0].event_count == 3


def test_two_clusters_by_gap():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:05:00Z"),
        _ev("2025-01-01T00:05:10Z"),
    ]
    r = analyze_event_clusters(events, gap_threshold_seconds=60)
    assert r.summary.total_clusters == 2
    assert r.clusters[0].event_count == 2
    assert r.clusters[1].event_count == 2


def test_burst_detection():
    events = [_ev(f"2025-01-01T00:00:{i:02d}Z") for i in range(6)]
    r = analyze_event_clusters(events, burst_min_events=5, burst_max_seconds=30)
    assert r.summary.burst_clusters == 1
    assert r.clusters[0].is_burst is True


def test_no_burst_when_too_slow():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
        _ev("2025-01-01T00:00:20Z"),
        _ev("2025-01-01T00:00:30Z"),
        _ev("2025-01-01T00:00:50Z"),
    ]
    r = analyze_event_clusters(events, burst_min_events=5, burst_max_seconds=30)
    assert r.clusters[0].is_burst is False


def test_campaign_detection():
    events = [
        _ev("2025-01-01T00:00:00Z", agent="a1"),
        _ev("2025-01-01T00:00:10Z", agent="a1"),
        _ev("2025-01-01T00:02:00Z", agent="a1"),
        _ev("2025-01-01T00:02:10Z", agent="a1"),
    ]
    r = analyze_event_clusters(events, gap_threshold_seconds=60, campaign_gap_seconds=300)
    assert r.summary.campaigns >= 1


def test_multi_agent_cluster():
    events = [
        _ev("2025-01-01T00:00:00Z", agent="a1"),
        _ev("2025-01-01T00:00:05Z", agent="a2"),
        _ev("2025-01-01T00:00:10Z", agent="a1"),
    ]
    r = analyze_event_clusters(events)
    assert r.summary.agents_involved == 2
    assert set(r.clusters[0].agents) == {"a1", "a2"}


def test_density():
    events = [
        _ev("2025-01-01T00:00:00Z"),
        _ev("2025-01-01T00:00:10Z"),
    ]
    r = analyze_event_clusters(events)
    assert r.clusters[0].density == 0.2


def test_format_text_header():
    r = analyze_event_clusters([])
    out = format_text(r)
    assert "Event Cluster Analysis" in out


def test_format_json():
    events = [_ev("2025-01-01T00:00:00Z")]
    r = analyze_event_clusters(events)
    out = format_json(r)
    assert '"total_clusters"' in out
    assert '"clusters"' in out


def test_no_timestamp_events_skipped():
    events = [{"agent": "a1", "tool": "read"}]
    r = analyze_event_clusters(events)
    assert r.summary.total_events == 0
