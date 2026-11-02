"""Tests for cross-session event linking."""
from __future__ import annotations

import json

from orbit_ir.session_link import (
    analyze_session_links,
    format_text,
    format_json,
    _load_events,
    SessionLink,
    SessionOverlap,
    SessionLinkReport,
    SessionLinkSummary,
)


def _ev(agent_id, session_id, resource="", timestamp="2025-01-01T00:00:00Z", **kwargs):
    return {"agent_id": agent_id, "session_id": session_id, "resource": resource, "timestamp": timestamp, **kwargs}


class TestAnalyzeSessionLinks:
    def test_empty_events(self):
        report = analyze_session_links([])
        assert report.summary.total_links == 0
        assert report.summary.sessions_analyzed == 0

    def test_single_session_no_links(self):
        events = [
            _ev("agent-1", "sess-A", "/data/x", "2025-01-01T00:01:00Z"),
            _ev("agent-2", "sess-A", "/data/y", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        assert report.summary.sessions_analyzed == 1
        agent_overlap_links = [l for l in report.links if l.link_type == "agent-overlap"]
        assert len(agent_overlap_links) == 0

    def test_agent_in_two_sessions(self):
        events = [
            _ev("agent-1", "sess-A", "", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-B", "", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        agent_links = [l for l in report.links if l.link_type == "agent-overlap"]
        assert len(agent_links) == 1
        assert "agent-1" in agent_links[0].agents
        assert "sess-A" in agent_links[0].sessions
        assert "sess-B" in agent_links[0].sessions

    def test_agent_in_three_sessions_high_confidence(self):
        events = [
            _ev("agent-1", "sess-A", "", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-B", "", "2025-01-01T00:02:00Z"),
            _ev("agent-1", "sess-C", "", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_session_links(events)
        agent_links = [l for l in report.links if l.link_type == "agent-overlap"]
        assert len(agent_links) == 1
        assert agent_links[0].confidence == "high"

    def test_shared_resource_across_sessions(self):
        events = [
            _ev("agent-1", "sess-A", "/shared/config.json", "2025-01-01T00:01:00Z"),
            _ev("agent-2", "sess-B", "/shared/config.json", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        resource_links = [l for l in report.links if l.link_type == "resource-shared"]
        assert len(resource_links) == 1
        assert "/shared/config.json" in resource_links[0].resources

    def test_temporal_overlap_with_shared_agent(self):
        events = [
            _ev("agent-1", "sess-A", "/x", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-A", "/y", "2025-01-01T00:10:00Z"),
            _ev("agent-1", "sess-B", "/z", "2025-01-01T00:05:00Z"),
            _ev("agent-2", "sess-B", "/w", "2025-01-01T00:08:00Z"),
        ]
        report = analyze_session_links(events)
        assert len(report.overlaps) >= 1
        overlap = report.overlaps[0]
        assert "agent-1" in overlap.shared_agents

    def test_no_temporal_overlap(self):
        events = [
            _ev("agent-1", "sess-A", "", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-A", "", "2025-01-01T00:02:00Z"),
            _ev("agent-2", "sess-B", "", "2025-01-01T00:10:00Z"),
            _ev("agent-2", "sess-B", "", "2025-01-01T00:11:00Z"),
        ]
        report = analyze_session_links(events)
        non_overlapping = [o for o in report.overlaps if o.overlap_start <= o.overlap_end]
        temporal_links = [l for l in report.links if l.link_type == "temporal-overlap"]
        assert len(temporal_links) == 0

    def test_no_session_id_skipped(self):
        events = [
            {"agent_id": "agent-1", "resource": "/x", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        report = analyze_session_links(events)
        assert report.summary.sessions_analyzed == 0

    def test_summary_counts(self):
        events = [
            _ev("agent-1", "sess-A", "/r1", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-B", "/r1", "2025-01-01T00:02:00Z"),
            _ev("agent-2", "sess-C", "/r2", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_session_links(events)
        assert report.summary.sessions_analyzed == 3

    def test_link_ids_unique(self):
        events = [
            _ev("a1", "s1", "/r", "2025-01-01T00:01:00Z"),
            _ev("a1", "s2", "/r", "2025-01-01T00:02:00Z"),
            _ev("a2", "s1", "/r", "2025-01-01T00:03:00Z"),
            _ev("a2", "s3", "/r", "2025-01-01T00:04:00Z"),
        ]
        report = analyze_session_links(events)
        ids = [l.link_id for l in report.links]
        assert len(ids) == len(set(ids))


class TestFormatText:
    def test_empty_report(self):
        report = SessionLinkReport(
            links=[], overlaps=[],
            summary=SessionLinkSummary(total_links=0),
        )
        text = format_text(report)
        assert "Cross-Session Event Linking Report" in text
        assert "Total links:            0" in text

    def test_with_links(self):
        events = [
            _ev("agent-1", "sess-A", "", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "sess-B", "", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        text = format_text(report)
        assert "SL-001" in text
        assert "agent-1" in text
        assert "agent-overlap" in text


class TestFormatJson:
    def test_empty_json(self):
        report = SessionLinkReport(
            links=[], overlaps=[],
            summary=SessionLinkSummary(total_links=0),
        )
        output = format_json(report)
        data = json.loads(output)
        assert data["summary"]["total_links"] == 0
        assert data["links"] == []

    def test_json_structure(self):
        events = [
            _ev("a1", "s1", "/res", "2025-01-01T00:01:00Z"),
            _ev("a1", "s2", "/res", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        output = format_json(report)
        data = json.loads(output)
        assert "links" in data
        assert "overlaps" in data
        assert "summary" in data

    def test_json_roundtrip(self):
        events = [
            _ev("a1", "s1", "", "2025-01-01T00:01:00Z"),
            _ev("a1", "s2", "", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_session_links(events)
        output = format_json(report)
        data = json.loads(output)
        assert isinstance(data["summary"]["total_links"], int)


class TestLoadEvents:
    def test_load_from_directory(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"agent_id": "a1", "session_id": "s1", "timestamp": "2025-01-01T00:01:00Z"}\n')
        events = _load_events(tmp_path)
        assert len(events) == 1

    def test_load_missing_dir(self, tmp_path):
        events = _load_events(tmp_path / "nope")
        assert events == []
