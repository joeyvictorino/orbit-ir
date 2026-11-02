"""Tests for behavior_cluster module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.behavior_cluster import (
    analyze_behavior_clusters,
    format_json,
    format_text,
    _build_profile,
    _cosine_similarity,
    _normalize_counts,
    _load_events,
)


class TestHelpers:
    def test_normalize_counts(self):
        result = _normalize_counts({"a": 3, "b": 1})
        assert abs(result["a"] - 0.75) < 0.01
        assert abs(result["b"] - 0.25) < 0.01

    def test_normalize_counts_empty(self):
        assert _normalize_counts({}) == {}

    def test_cosine_similarity_identical(self):
        vec = {"a": 0.5, "b": 0.5}
        assert abs(_cosine_similarity(vec, vec) - 1.0) < 0.01

    def test_cosine_similarity_orthogonal(self):
        vec_a = {"a": 1.0}
        vec_b = {"b": 1.0}
        assert _cosine_similarity(vec_a, vec_b) == 0.0

    def test_cosine_similarity_empty(self):
        assert _cosine_similarity({}, {}) == 1.0

    def test_build_profile(self):
        events = [
            {"agent_id": "a1", "tool": "read_file", "resource": "/data", "timestamp": "2026-01-01T00:00:00Z"},
            {"agent_id": "a1", "tool": "read_file", "resource": "/logs", "timestamp": "2026-01-01T00:01:00Z"},
            {"agent_id": "a1", "tool": "write_file", "resource": "/data", "timestamp": "2026-01-01T00:02:00Z"},
        ]
        p = _build_profile("a1", events)
        assert p.agent_id == "a1"
        assert p.event_count == 3
        assert p.unique_tools == 2
        assert p.tool_counts["read_file"] == 2
        assert p.tool_counts["write_file"] == 1


class TestAnalyzeBehaviorClusters:
    def test_empty_events(self):
        report = analyze_behavior_clusters([])
        assert report.summary.total_agents == 0
        assert report.summary.total_clusters == 0

    def test_single_agent(self):
        events = [
            {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
        ]
        report = analyze_behavior_clusters(events)
        assert report.summary.total_agents == 1
        assert report.summary.total_clusters == 1

    def test_similar_agents_cluster(self):
        events = []
        for agent in ["a1", "a2", "a3"]:
            for i in range(10):
                events.append({
                    "agent_id": agent,
                    "tool": "read_file",
                    "resource": "/data",
                    "timestamp": f"2026-01-01T00:{i:02d}:00Z",
                })
        report = analyze_behavior_clusters(events, similarity_threshold=0.3)
        assert report.summary.total_clusters >= 1
        biggest = max(report.clusters, key=lambda c: len(c.members))
        assert len(biggest.members) >= 2

    def test_dissimilar_agents_separate(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "reader",
                "tool": "read_file",
                "resource": "/data",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10):
            events.append({
                "agent_id": "writer",
                "tool": "write_file",
                "resource": "/output",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10):
            events.append({
                "agent_id": "deleter",
                "tool": "delete_file",
                "resource": "/tmp",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_behavior_clusters(events, similarity_threshold=0.5)
        assert report.summary.total_clusters >= 2

    def test_outlier_detection(self):
        events = []
        for agent in ["norm1", "norm2", "norm3", "norm4"]:
            for i in range(10):
                events.append({
                    "agent_id": agent,
                    "tool": "read_file",
                    "resource": "/data",
                    "timestamp": f"2026-01-01T00:{i:02d}:00Z",
                })
        for i in range(10):
            events.append({
                "agent_id": "weirdo",
                "tool": f"exotic_tool_{i}",
                "resource": f"/unusual/path_{i}",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_behavior_clusters(events, similarity_threshold=0.5)
        outlier_ids = {o.agent_id for o in report.outliers}
        if outlier_ids:
            assert "weirdo" in outlier_ids

    def test_cohesion_range(self):
        events = []
        for agent in ["a1", "a2"]:
            for i in range(5):
                events.append({
                    "agent_id": agent,
                    "tool": "read",
                    "timestamp": f"2026-01-01T00:{i:02d}:00Z",
                })
        report = analyze_behavior_clusters(events)
        for c in report.clusters:
            assert 0.0 <= c.cohesion <= 1.0

    def test_profiles_populated(self):
        events = [
            {"agent_id": "a1", "tool": "read", "resource": "/x", "timestamp": "2026-01-01T00:00:00Z"},
            {"agent_id": "a2", "tool": "write", "resource": "/y", "timestamp": "2026-01-01T00:01:00Z"},
        ]
        report = analyze_behavior_clusters(events)
        assert len(report.profiles) == 2
        ids = {p.agent_id for p in report.profiles}
        assert ids == {"a1", "a2"}


class TestFormatText:
    def test_format_text_empty(self):
        report = analyze_behavior_clusters([])
        text = format_text(report)
        assert "Agent Behavioral Clustering Report" in text
        assert "Total agents:           0" in text

    def test_format_text_with_clusters(self):
        events = [
            {"agent_id": "a1", "tool": "read", "timestamp": "2026-01-01T00:00:00Z"},
            {"agent_id": "a2", "tool": "read", "timestamp": "2026-01-01T00:01:00Z"},
        ]
        report = analyze_behavior_clusters(events)
        text = format_text(report)
        assert "CLU-" in text


class TestFormatJson:
    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "tool": "read", "timestamp": "2026-01-01T00:00:00Z"},
        ]
        report = analyze_behavior_clusters(events)
        data = json.loads(format_json(report))
        assert "clusters" in data
        assert "summary" in data
        assert "profiles" in data

    def test_format_json_empty(self):
        data = json.loads(format_json(analyze_behavior_clusters([])))
        assert data["summary"]["total_agents"] == 0


class TestLoadEvents:
    def test_load_events(self, tmp_path):
        events = [{"agent_id": "a1", "tool": "read", "timestamp": "2026-01-01T00:00:00Z"}]
        (tmp_path / "events.jsonl").write_text(json.dumps(events[0]))
        loaded = _load_events(tmp_path)
        assert len(loaded) == 1

    def test_load_events_empty(self, tmp_path):
        assert _load_events(tmp_path) == []
