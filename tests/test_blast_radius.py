"""Tests for blast radius estimation."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from orbit_ir.blast_radius import (
    BlastRadiusEstimator,
    estimate_blast_radius,
    format_blast_radius_text,
    _compute_score,
    _extract_agents,
    _extract_resources,
    _extract_data_flows,
    _parse_ts,
)


def _write_events(tmp: Path, events: list[dict]) -> Path:
    p = tmp / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp


def test_extract_agents_basic():
    event = {"agent_id": "a1", "dst_agent": "a2"}
    agents = _extract_agents(event)
    assert "a1" in agents
    assert "a2" in agents


def test_extract_agents_empty():
    assert _extract_agents({}) == set()


def test_extract_resources_with_fields():
    event = {"target": "/etc/passwd", "database": "users_db"}
    resources = _extract_resources(event)
    assert "/etc/passwd" in resources
    assert "users_db" in resources


def test_extract_resources_with_ip():
    event = {"message": "connected to 192.168.1.100"}
    resources = _extract_resources(event)
    assert "ip:192.168.1.100" in resources


def test_extract_resources_ignores_localhost():
    event = {"message": "listening on 127.0.0.1"}
    resources = _extract_resources(event)
    assert "ip:127.0.0.1" not in resources


def test_extract_data_flows():
    events = [
        {"src_agent": "a1", "dst_agent": "a2"},
        {"src_agent": "a2", "dst_agent": "a3"},
        {"src_agent": "a1", "dst_agent": "a2"},  # duplicate
    ]
    flows = _extract_data_flows(events)
    assert len(flows) == 2
    assert ("a1", "a2") in flows
    assert ("a2", "a3") in flows


def test_extract_data_flows_empty():
    assert _extract_data_flows([]) == []


def test_parse_ts_valid():
    ts = _parse_ts("2024-01-15T10:30:00Z")
    assert ts is not None
    assert ts.hour == 10


def test_parse_ts_invalid():
    assert _parse_ts("not a timestamp") is None


def test_parse_ts_none():
    assert _parse_ts(None) is None


def test_compute_score_zero():
    assert _compute_score(0, 0, 0, 0.0) == 0.0


def test_compute_score_max():
    score = _compute_score(10, 20, 15, 7200)
    assert score == 10.0


def test_compute_score_partial():
    score = _compute_score(3, 5, 4, 1800)
    assert 0.0 < score < 10.0


def test_estimator_empty_dir():
    with tempfile.TemporaryDirectory() as tmp:
        est = estimate_blast_radius(Path(tmp))
        assert est.blast_radius_score == 0.0
        assert est.affected_agents == []
        assert est.affected_resources == []


def test_estimator_with_events():
    events = [
        {"agent_id": "a1", "dst_agent": "a2", "target": "/data/secret.txt",
         "timestamp": "2024-01-15T10:00:00Z", "severity": "high"},
        {"agent_id": "a2", "dst_agent": "a3", "target": "/data/config.yaml",
         "timestamp": "2024-01-15T11:00:00Z", "severity": "critical"},
        {"agent_id": "a3", "resource": "database_main",
         "timestamp": "2024-01-15T12:00:00Z", "severity": "medium"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        est = estimate_blast_radius(Path(tmp))
        assert len(est.affected_agents) == 3
        assert est.blast_radius_score > 0
        assert est.timeline_span_seconds == 7200.0
        assert "high" in est.severity_distribution
        assert "critical" in est.severity_distribution


def test_estimator_data_flows():
    events = [
        {"src_agent": "sender", "dst_agent": "receiver"},
        {"source": "db1", "destination": "export_service"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        est = estimate_blast_radius(Path(tmp))
        assert len(est.data_flows) == 2


def test_estimator_to_dict():
    events = [
        {"agent_id": "a1", "target": "res1", "severity": "low"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        est = estimate_blast_radius(Path(tmp))
        d = est.to_dict()
        assert "total_events" in d
        assert "blast_radius_score" in d
        assert "affected_agents" in d
        assert "data_flows" in d
        assert d["total_events"] == 1


def test_format_text_below_threshold():
    data = {"blast_radius_score": 1.0, "total_events": 5}
    text = format_blast_radius_text(data, threshold=5.0)
    assert "below threshold" in text


def test_format_text_critical():
    data = {
        "blast_radius_score": 8.5,
        "total_events": 100,
        "affected_agent_count": 5,
        "affected_agents": ["a1", "a2", "a3", "a4", "a5"],
        "affected_resource_count": 3,
        "affected_resources": ["r1", "r2", "r3"],
        "affected_credentials": [],
        "data_flows": [{"source": "a1", "destination": "a2"}],
        "data_flow_count": 1,
        "timeline_span_seconds": 3600.0,
        "severity_distribution": {"critical": 10, "high": 20},
    }
    text = format_blast_radius_text(data)
    assert "CRITICAL" in text
    assert "8.5" in text
    assert "a1" in text


def test_format_text_low():
    data = {
        "blast_radius_score": 1.0,
        "total_events": 2,
        "affected_agent_count": 1,
        "affected_agents": ["a1"],
        "affected_resource_count": 0,
        "affected_resources": [],
        "affected_credentials": [],
        "data_flows": [],
        "data_flow_count": 0,
        "timeline_span_seconds": 60.0,
        "severity_distribution": {"low": 2},
    }
    text = format_blast_radius_text(data)
    assert "LOW" in text


def test_estimator_single_file():
    events = [
        {"agent_id": "a1", "severity": "high"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "single.json"
        p.write_text(json.dumps(events), encoding="utf-8")
        est = estimate_blast_radius(p)
        assert est.to_dict()["total_events"] == 1
