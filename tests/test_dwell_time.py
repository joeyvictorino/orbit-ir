"""Tests for orbit_ir.dwell_time — dwell time analysis."""

import json
import textwrap
from pathlib import Path

from orbit_ir.dwell_time import (
    DwellTimeReport,
    PhaseBreakdown,
    analyze,
    format_json,
    format_text,
)


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp_path


def test_empty_evidence(tmp_path):
    r = analyze(tmp_path)
    assert r.event_count == 0
    assert r.total_duration_seconds == 0
    assert r.bottleneck == "no timestamped events"


def test_single_event(tmp_path):
    events = [{"timestamp": "2025-01-01T00:00:00Z", "type": "scan"}]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.event_count == 1
    assert r.total_duration_seconds == 0


def test_basic_dwell_time(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "type": "scan", "action": "enumerate"},
        {"timestamp": "2025-01-01T01:00:00Z", "type": "exploit", "action": "exploit"},
        {"timestamp": "2025-01-01T03:00:00Z", "type": "alert", "action": "detect"},
        {"timestamp": "2025-01-01T04:00:00Z", "type": "response", "action": "remediate"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.event_count == 4
    assert r.total_duration_seconds == 4 * 3600
    # recon at T+0, exploit at T+1h -> detect at T+3h: time_to_detect = 2h (from exploit)
    assert r.time_to_detect_seconds is not None
    assert r.time_to_detect_seconds == 2 * 3600  # exploit(1h) to detect(3h)
    assert r.time_to_respond_seconds == 3600  # detect(3h) to respond(4h)


def test_no_detection_phase(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T02:00:00Z", "action": "exploit"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.time_to_detect_seconds is None
    assert r.time_to_respond_seconds is None


def test_benchmark_comparison(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "probe"},
        {"timestamp": "2025-01-01T01:00:00Z", "action": "exploit"},
        {"timestamp": "2025-01-02T00:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-02T12:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, benchmarks={"time_to_detect_days": 200, "total_duration_days": 270})
    assert len(r.benchmarks) >= 1
    # Detect took ~23h = ~0.96 days vs 200d benchmark -> excellent
    detect_bench = next((b for b in r.benchmarks if b.metric == "Time to Detect"), None)
    assert detect_bench is not None
    assert detect_bench.assessment == "excellent"


def test_phase_breakdown(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T00:30:00Z", "action": "enumerate"},
        {"timestamp": "2025-01-01T01:00:00Z", "action": "exploit"},
        {"timestamp": "2025-01-01T02:00:00Z", "action": "bypass"},
        {"timestamp": "2025-01-01T03:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.phase_breakdown.recon_seconds == 1800  # 30 min between two recon events
    assert r.phase_breakdown.exploitation_seconds == 3600  # 1h between two exploit events


def test_bottleneck_identification(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T00:10:00Z", "action": "probe"},
        {"timestamp": "2025-01-01T10:00:00Z", "action": "exploit"},
        {"timestamp": "2025-01-01T10:05:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    # Recon phase: 10 min, exploit: 0 (single event), detect: 0 (single event)
    assert r.bottleneck == "recon"


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T01:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-01T02:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Dwell Time Analysis" in text
    assert "Phase Breakdown" in text
    assert "Events analyzed:" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T01:00:00Z", "action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "total_duration_seconds" in j
    assert "phase_breakdown" in j
    assert "benchmarks" in j


def test_json_file_input(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "scan"},
        {"timestamp": "2025-01-01T05:00:00Z", "action": "exploit"},
    ]
    (tmp_path / "data.json").write_text(json.dumps(events), encoding="utf-8")
    r = analyze(tmp_path)
    assert r.event_count == 2
    assert r.total_duration_seconds == 5 * 3600


def test_events_without_timestamps(tmp_path):
    events = [
        {"action": "scan"},
        {"timestamp": "2025-01-01T00:00:00Z", "action": "exploit"},
        {"action": "detect"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.event_count == 1


def test_custom_benchmarks(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "exploit"},
        {"timestamp": "2025-01-01T12:00:00Z", "action": "detect"},
        {"timestamp": "2025-01-02T00:00:00Z", "action": "contain"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, benchmarks={"time_to_detect_days": 0.25, "total_duration_days": 1})
    detect_bench = next((b for b in r.benchmarks if b.metric == "Time to Detect"), None)
    assert detect_bench is not None
    assert detect_bench.actual_days == 0.5  # 12 hours
    assert detect_bench.assessment == "concerning"  # 2x benchmark


def test_persistence_phase(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "backdoor"},
        {"timestamp": "2025-01-01T06:00:00Z", "action": "persist"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.phase_breakdown.persistence_seconds == 6 * 3600
