"""Tests for composite anomaly scoring."""
from __future__ import annotations

import json

from orbit_ir.anomaly_score import (
    score_anomalies,
    format_text,
    format_json,
    _load_events,
    _mean,
    _std,
    _z_score_norm,
    _risk_level,
    _timing_regularity_score,
    AgentAnomalyScore,
    AnomalyScoreReport,
    AnomalyScoreSummary,
)


def _ev(agent_id, tool="read_file", resource="", timestamp="2025-01-01T00:00:00Z", **kwargs):
    return {"agent_id": agent_id, "tool": tool, "resource": resource, "timestamp": timestamp, **kwargs}


class TestHelpers:
    def test_mean_empty(self):
        assert _mean([]) == 0.0

    def test_mean_values(self):
        assert _mean([2, 4, 6]) == 4.0

    def test_std_single(self):
        assert _std([5]) == 0.0

    def test_std_values(self):
        result = _std([2, 4, 6])
        assert 1.6 < result < 1.7

    def test_z_score_norm_zero_std(self):
        assert _z_score_norm(5, 3, 0) == 0.5
        assert _z_score_norm(1, 3, 0) == 0.0

    def test_z_score_norm_normal(self):
        score = _z_score_norm(10, 5, 2.5)
        assert 0.0 <= score <= 1.0

    def test_z_score_norm_clamped(self):
        score = _z_score_norm(100, 5, 1)
        assert score == 1.0
        score = _z_score_norm(-100, 5, 1)
        assert score == 0.0

    def test_risk_level(self):
        assert _risk_level(0.9) == "critical"
        assert _risk_level(0.7) == "high"
        assert _risk_level(0.5) == "medium"
        assert _risk_level(0.2) == "low"

    def test_timing_regularity_few_timestamps(self):
        assert _timing_regularity_score(["a", "b"]) == 0.0

    def test_timing_regularity_identical(self):
        score = _timing_regularity_score(["2025-01-01T00:00:00Z"] * 5)
        assert score > 0.0


class TestScoreAnomalies:
    def test_empty_events(self):
        report = score_anomalies([])
        assert report.summary.total_agents == 0
        assert report.summary.agents_scored == 0

    def test_single_agent(self):
        events = [_ev("agent-1", "read_file", "/x", f"2025-01-01T00:0{i}:00Z") for i in range(5)]
        report = score_anomalies(events)
        assert report.summary.agents_scored == 1
        assert report.scores[0].agent_id == "agent-1"
        assert 0.0 <= report.scores[0].composite_score <= 1.0

    def test_multiple_agents_ranked(self):
        events = []
        for i in range(3):
            events.append(_ev("normal", "read_file", f"/r{i}", f"2025-01-01T00:0{i}:00Z"))
        for i in range(20):
            events.append(_ev("suspicious", f"tool_{i}", f"/res_{i}", f"2025-01-01T00:{i:02d}:00Z"))
        report = score_anomalies(events)
        assert report.summary.agents_scored == 2
        assert report.scores[0].composite_score >= report.scores[1].composite_score

    def test_error_rate_scoring(self):
        events = [
            _ev("error-agent", "read_file", "/x", "2025-01-01T00:01:00Z", status="error"),
            _ev("error-agent", "write_file", "/y", "2025-01-01T00:02:00Z", status="denied"),
            _ev("error-agent", "api_call", "/z", "2025-01-01T00:03:00Z", status="failed"),
            _ev("good-agent", "read_file", "/a", "2025-01-01T00:01:00Z", status="success"),
            _ev("good-agent", "read_file", "/b", "2025-01-01T00:02:00Z", status="success"),
            _ev("good-agent", "read_file", "/c", "2025-01-01T00:03:00Z", status="success"),
        ]
        report = score_anomalies(events)
        error_agent = next(s for s in report.scores if s.agent_id == "error-agent")
        good_agent = next(s for s in report.scores if s.agent_id == "good-agent")
        error_dim = next(d for d in error_agent.dimensions if d.name == "error-rate")
        good_dim = next(d for d in good_agent.dimensions if d.name == "error-rate")
        assert error_dim.score > good_dim.score

    def test_payload_volume_scoring(self):
        events = [
            _ev("big", "upload", "/data", "2025-01-01T00:01:00Z", bytes=500000),
            _ev("big", "upload", "/data2", "2025-01-01T00:02:00Z", bytes=500000),
            _ev("big", "read", "/data3", "2025-01-01T00:03:00Z"),
            _ev("small", "read", "/x", "2025-01-01T00:01:00Z", bytes=100),
            _ev("small", "read", "/y", "2025-01-01T00:02:00Z", bytes=100),
            _ev("small", "read", "/z", "2025-01-01T00:03:00Z"),
        ]
        report = score_anomalies(events)
        big = next(s for s in report.scores if s.agent_id == "big")
        small = next(s for s in report.scores if s.agent_id == "small")
        big_vol = next(d for d in big.dimensions if d.name == "payload-volume")
        small_vol = next(d for d in small.dimensions if d.name == "payload-volume")
        assert big_vol.score > small_vol.score

    def test_dimensions_present(self):
        events = [_ev("a1", "read_file", "/x", f"2025-01-01T00:0{i}:00Z") for i in range(4)]
        report = score_anomalies(events)
        dims = {d.name for d in report.scores[0].dimensions}
        assert "tool-frequency" in dims
        assert "timing-regularity" in dims
        assert "resource-breadth" in dims
        assert "action-diversity" in dims
        assert "error-rate" in dims
        assert "payload-volume" in dims

    def test_top_anomaly_set(self):
        events = [_ev("a1", "read_file", "/x", "2025-01-01T00:01:00Z")]
        report = score_anomalies(events)
        assert report.scores[0].top_anomaly != ""

    def test_summary_stats(self):
        events = [
            _ev("a1", "t1", "/r1", "2025-01-01T00:01:00Z"),
            _ev("a2", "t2", "/r2", "2025-01-01T00:02:00Z"),
        ]
        report = score_anomalies(events)
        assert report.summary.avg_composite_score >= 0.0
        assert report.summary.max_composite_score >= report.summary.avg_composite_score

    def test_claimed_tool_fallback(self):
        events = [
            {"agent_id": "a1", "claimed_tool": "read_file", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        report = score_anomalies(events)
        assert report.summary.agents_scored == 1

    def test_no_agent_id_skipped(self):
        events = [{"tool": "read_file", "timestamp": "2025-01-01T00:01:00Z"}]
        report = score_anomalies(events)
        assert report.summary.agents_scored == 0


class TestFormatText:
    def test_empty_report(self):
        report = AnomalyScoreReport(
            scores=[],
            summary=AnomalyScoreSummary(total_agents=0, agents_scored=0),
        )
        text = format_text(report)
        assert "Composite Anomaly Score Report" in text
        assert "Agents scored:          0" in text

    def test_with_scores(self):
        events = [_ev("a1", "read_file", "/x", f"2025-01-01T00:0{i}:00Z") for i in range(5)]
        report = score_anomalies(events)
        text = format_text(report)
        assert "a1" in text
        assert "tool-frequency" in text


class TestFormatJson:
    def test_empty_json(self):
        report = AnomalyScoreReport(
            scores=[],
            summary=AnomalyScoreSummary(total_agents=0, agents_scored=0),
        )
        output = format_json(report)
        data = json.loads(output)
        assert data["scores"] == []
        assert data["summary"]["agents_scored"] == 0

    def test_json_structure(self):
        events = [_ev("a1", "t1", "/r", "2025-01-01T00:01:00Z")]
        report = score_anomalies(events)
        output = format_json(report)
        data = json.loads(output)
        assert "scores" in data
        assert "summary" in data
        assert "dimensions" in data["scores"][0]
        assert "composite_score" in data["scores"][0]

    def test_json_roundtrip(self):
        events = [_ev("a1", "t1", "/r", "2025-01-01T00:01:00Z")]
        report = score_anomalies(events)
        output = format_json(report)
        data = json.loads(output)
        assert isinstance(data["summary"]["avg_composite_score"], float)


class TestLoadEvents:
    def test_load_from_dir(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"agent_id": "a1"}\n')
        events = _load_events(tmp_path)
        assert len(events) == 1

    def test_load_missing(self, tmp_path):
        events = _load_events(tmp_path / "nope")
        assert events == []
