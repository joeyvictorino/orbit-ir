"""Tests for the impact analysis module."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.impact import (
    ImpactAnalyzer,
    ImpactAssessment,
    analyze_impact,
    format_impact_text,
    _score_impact,
    _is_data_store_event,
    _is_api_event,
    _extract_agents,
    _estimate_data_volume,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "timestamp": "2026-01-15T10:00:00Z",
            "agent_id": "agent-alpha",
            "type": "api_call",
            "tool_name": "read_file",
            "resource": "config.yaml",
            "size": 1024,
        },
        {
            "timestamp": "2026-01-15T10:01:00Z",
            "agent_id": "agent-alpha",
            "type": "api_call",
            "endpoint": "/api/secrets",
            "size": 2048,
        },
        {
            "timestamp": "2026-01-15T10:02:00Z",
            "agent_id": "agent-beta",
            "type": "database_query",
            "database": "user_db",
            "table": "credentials",
            "size": 4096,
        },
        {
            "timestamp": "2026-01-15T10:03:00Z",
            "src_agent": "agent-alpha",
            "dst_agent": "agent-gamma",
            "type": "lateral_movement",
            "destination": "internal-service",
        },
        {
            "timestamp": "2026-01-15T10:04:00Z",
            "agent_id": "agent-gamma",
            "type": "tool_call",
            "tool_name": "write_file",
            "resource": "s3://bucket/exfil",
            "size": 8192,
        },
    ]
    edir = tmp_path / "evidence"
    edir.mkdir()
    (edir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return edir


@pytest.fixture
def detections() -> list[dict]:
    return [
        {
            "id": "det-001",
            "type": "credential_access",
            "severity": "high",
            "timestamp": "2026-01-15T10:01:30Z",
        },
        {
            "id": "det-002",
            "type": "lateral_movement",
            "severity": "critical",
            "timestamp": "2026-01-15T10:03:30Z",
        },
        {
            "id": "det-003",
            "type": "data_exfiltration",
            "severity": "critical",
            "timestamp": "2026-01-15T10:04:30Z",
        },
    ]


class TestScoreImpact:
    def test_low_score(self):
        score, level = _score_impact(0, 0, 0, 0, "low")
        assert level == "low"
        assert score < 2.5

    def test_high_score(self):
        score, level = _score_impact(4, 3, 20, 1024 * 1024, "critical")
        assert level in ("critical", "high")
        assert score >= 4.5

    def test_medium_score(self):
        score, level = _score_impact(2, 1, 5, 1000, "medium")
        assert level in ("medium", "low")


class TestHelpers:
    def test_is_data_store_event(self):
        assert _is_data_store_event({"database": "pg", "type": "query"})
        assert _is_data_store_event({"resource": "s3://bucket/key"})
        assert not _is_data_store_event({"type": "log_message", "text": "hello"})

    def test_is_api_event(self):
        assert _is_api_event({"type": "api_call"})
        assert _is_api_event({"tool_name": "write_file"})
        assert _is_api_event({"endpoint": "/api/data"})
        assert not _is_api_event({"type": "log", "message": "info"})

    def test_extract_agents(self):
        agents = _extract_agents({
            "agent_id": "a1",
            "dst_agent": "a2",
        })
        assert agents == {"a1", "a2"}

    def test_extract_agents_empty(self):
        assert _extract_agents({"type": "log"}) == set()

    def test_estimate_data_volume(self):
        events = [
            {"size": 100},
            {"bytes": 200},
            {"content_length": 300},
            {"body": "hello"},
        ]
        vol = _estimate_data_volume(events)
        assert vol == 100 + 200 + 300 + 5


class TestImpactAnalyzer:
    def test_analyze_with_evidence(self, evidence_dir, detections):
        analyzer = ImpactAnalyzer(window_seconds=300.0)
        results = analyzer.analyze(detections, evidence_dir)
        assert len(results) == 3
        for r in results:
            assert "detection_id" in r
            assert "impact_score" in r
            assert "impact_level" in r
            assert r["impact_level"] in ("low", "medium", "high", "critical")

    def test_analyze_empty_results(self, evidence_dir):
        analyzer = ImpactAnalyzer()
        results = analyzer.analyze([], evidence_dir)
        assert results == []

    def test_analyze_no_evidence(self, tmp_path, detections):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        analyzer = ImpactAnalyzer()
        results = analyzer.analyze(detections, empty_dir)
        assert len(results) == 3
        for r in results:
            assert r["event_count"] == 0

    def test_analyze_nonexistent_dir(self, tmp_path, detections):
        analyzer = ImpactAnalyzer()
        results = analyzer.analyze(detections, tmp_path / "nope")
        assert len(results) == 3

    def test_citations_capped(self, evidence_dir, detections):
        analyzer = ImpactAnalyzer(window_seconds=600.0)
        results = analyzer.analyze(detections, evidence_dir)
        for r in results:
            assert len(r["citations"]) <= 10

    def test_agents_detected(self, evidence_dir, detections):
        analyzer = ImpactAnalyzer(window_seconds=600.0)
        results = analyzer.analyze(detections, evidence_dir)
        all_agents = set()
        for r in results:
            all_agents.update(r["agents_affected"])
        assert "agent-alpha" in all_agents

    def test_data_stores_detected(self, evidence_dir, detections):
        analyzer = ImpactAnalyzer(window_seconds=600.0)
        results = analyzer.analyze(detections, evidence_dir)
        all_stores = set()
        for r in results:
            all_stores.update(r["data_stores_accessed"])
        assert len(all_stores) > 0

    def test_custom_window(self, evidence_dir, detections):
        narrow = ImpactAnalyzer(window_seconds=30.0)
        wide = ImpactAnalyzer(window_seconds=600.0)
        narrow_results = narrow.analyze(detections, evidence_dir)
        wide_results = wide.analyze(detections, evidence_dir)
        narrow_total = sum(r["event_count"] for r in narrow_results)
        wide_total = sum(r["event_count"] for r in wide_results)
        assert wide_total >= narrow_total


class TestAnalyzeImpact:
    def test_convenience_function(self, evidence_dir, detections):
        results = analyze_impact(detections, evidence_dir)
        assert len(results) == 3

    def test_min_severity_filter(self, evidence_dir, detections):
        results = analyze_impact(detections, evidence_dir, min_severity="critical")
        assert len(results) == 2
        for r in results:
            assert r["severity"] == "critical"

    def test_min_severity_all(self, evidence_dir, detections):
        results = analyze_impact(detections, evidence_dir, min_severity="low")
        assert len(results) == 3


class TestFormatImpactText:
    def test_format_output(self, evidence_dir, detections):
        results = analyze_impact(detections, evidence_dir)
        text = format_impact_text(results)
        assert "Impact Assessment" in text
        assert "det-001" in text
        assert "det-002" in text
        assert "critical" in text.lower() or "high" in text.lower()

    def test_format_empty(self):
        text = format_impact_text([])
        assert "No detections" in text

    def test_summary_line(self, evidence_dir, detections):
        results = analyze_impact(detections, evidence_dir)
        text = format_impact_text(results)
        assert "Summary:" in text


class TestImpactAssessment:
    def test_to_dict(self):
        a = ImpactAssessment(
            detection_id="x",
            detection_type="test",
            severity="high",
            agents_affected=["a1"],
            impact_score=5.0,
            impact_level="high",
        )
        d = a.to_dict()
        assert d["detection_id"] == "x"
        assert d["impact_level"] == "high"
        assert isinstance(d["agents_affected"], list)
