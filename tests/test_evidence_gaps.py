"""Tests for evidence gap detection."""

import json
from pathlib import Path

import pytest

from orbit_ir.evidence_gaps import analyze, format_text, format_json, GapReport


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    d = tmp_path / "evidence"
    d.mkdir()
    f = d / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return d


def test_empty_evidence(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "empty.jsonl").write_text("", encoding="utf-8")
    r = analyze(d)
    assert r.metrics.total_events == 0
    assert r.metrics.total_gaps == 0


def test_single_event(tmp_path):
    events = [{"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "scan"}]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.metrics.total_events == 1
    assert r.metrics.total_gaps == 0


def test_no_gaps(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "scan"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "a1", "action": "detect"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "a1", "action": "report"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    assert r.metrics.total_gaps == 0
    assert r.metrics.coverage_pct == 100.0


def test_detect_gap(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "scan"},
        {"timestamp": "2024-01-01T00:10:00Z", "agent_id": "a2", "action": "respond"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    assert r.metrics.total_gaps == 1
    assert r.gaps[0].duration_seconds == 600.0
    assert r.gaps[0].preceding_agent == "a1"
    assert r.gaps[0].following_agent == "a2"


def test_multiple_gaps(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
        {"timestamp": "2024-01-01T00:10:00Z", "agent_id": "a1", "action": "mid"},
        {"timestamp": "2024-01-01T00:20:00Z", "agent_id": "a2", "action": "end"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    assert r.metrics.total_gaps == 2


def test_coverage_calculation(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
        {"timestamp": "2024-01-01T01:00:00Z", "agent_id": "a1", "action": "end"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    assert r.metrics.coverage_pct < 100.0


def test_gap_score_bounded(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
        {"timestamp": "2024-01-01T06:00:00Z", "agent_id": "a2", "action": "end"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    assert 0.0 <= r.metrics.gap_score <= 1.0


def test_gaps_sorted_by_duration(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "a"},
        {"timestamp": "2024-01-01T00:10:00Z", "agent_id": "a1", "action": "b"},
        {"timestamp": "2024-01-01T00:30:00Z", "agent_id": "a1", "action": "c"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    if len(r.gaps) >= 2:
        assert r.gaps[0].duration_seconds >= r.gaps[1].duration_seconds


def test_timeline_boundaries(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
        {"timestamp": "2024-01-01T01:00:00Z", "agent_id": "a1", "action": "end"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.timeline_start == "2024-01-01T00:00:00Z"
    assert r.timeline_end == "2024-01-01T01:00:00Z"


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
        {"timestamp": "2024-01-01T00:10:00Z", "agent_id": "a2", "action": "end"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d, gap_threshold_seconds=300)
    text = format_text(r)
    assert "Evidence Gap Analysis" in text
    assert "Gaps detected" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "start"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    j = format_json(r)
    data = json.loads(j)
    assert "metrics" in data
    assert "gaps" in data


def test_custom_threshold(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "a"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "a1", "action": "b"},
    ]
    d = _write_events(tmp_path, events)
    r_high = analyze(d, gap_threshold_seconds=300)
    r_low = analyze(d, gap_threshold_seconds=60)
    assert r_high.metrics.total_gaps == 0
    assert r_low.metrics.total_gaps == 1
