"""Tests for timeline differential analysis."""
from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.diff_timeline import (
    diff_timelines,
    detect_timing_shifts,
    format_diff_text,
    load_and_diff,
    summarize_diff,
)


def test_diff_identical_timelines():
    events = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    diff = diff_timelines(events, events)
    assert len(diff.added) == 0
    assert len(diff.removed) == 0
    assert len(diff.modified) == 0


def test_diff_added_events():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    diff = diff_timelines(baseline, compare)
    assert len(diff.added) == 1
    assert diff.added[0]["id"] == "e2"
    assert len(diff.removed) == 0


def test_diff_removed_events():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    diff = diff_timelines(baseline, compare)
    assert len(diff.removed) == 1
    assert diff.removed[0]["id"] == "e2"
    assert len(diff.added) == 0


def test_diff_modified_events():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "exfil"},
    ]
    diff = diff_timelines(baseline, compare)
    assert len(diff.modified) == 1
    old, new = diff.modified[0]
    assert old["action"] == "scan"
    assert new["action"] == "exfil"


def test_diff_empty_timelines():
    diff = diff_timelines([], [])
    assert len(diff.added) == 0
    assert len(diff.removed) == 0
    assert len(diff.modified) == 0


def test_detect_timing_shifts():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:05:00Z", "agent_id": "a1", "action": "scan"},
    ]
    shifts = detect_timing_shifts(baseline, compare, threshold_seconds=60.0)
    assert len(shifts) == 1
    assert shifts[0]["shift_seconds"] == 300.0
    assert shifts[0]["direction"] == "later"


def test_detect_timing_shifts_below_threshold():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:30Z", "agent_id": "a1", "action": "scan"},
    ]
    shifts = detect_timing_shifts(baseline, compare, threshold_seconds=60.0)
    assert len(shifts) == 0


def test_summarize_diff():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "exfil"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "move"},
    ]
    diff = diff_timelines(baseline, compare)
    s = summarize_diff(diff)
    assert s["added"] == 1
    assert s["modified"] == 1
    assert s["removed"] == 0


def test_format_diff_text():
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    diff = diff_timelines(baseline, compare)
    text = format_diff_text(diff)
    assert "Timeline Differential" in text
    assert "Added" in text
    assert "Removed" in text


def test_load_and_diff(tmp_path: Path):
    baseline = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    compare = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "exfil"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "move"},
    ]
    b_path = tmp_path / "baseline.json"
    c_path = tmp_path / "compare.json"
    b_path.write_text(json.dumps(baseline))
    c_path.write_text(json.dumps(compare))

    diff = load_and_diff(b_path, c_path)
    assert len(diff.added) == 1
    assert len(diff.modified) == 1


def test_diff_with_match_keys():
    baseline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan", "target": "host-1"},
    ]
    compare = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan", "target": "host-2"},
    ]
    diff = diff_timelines(baseline, compare, match_keys=["agent_id", "action"])
    assert len(diff.modified) == 1
    assert len(diff.added) == 0
    assert len(diff.removed) == 0
