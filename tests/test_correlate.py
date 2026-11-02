"""Tests for orbit_ir.correlate."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.correlate import correlate_events, format_correlate_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_basic_correlation(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:00Z"},
        {"event_id": "m2", "agent_id": "a1", "timestamp": "2026-07-08T18:00:02Z"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:01Z",
         "claimed_tool": "http_get", "actual_tool": "http_get"},
    ])
    _write_jsonl(ev / "control_plane.jsonl", [
        {"event_id": "cp1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:03Z", "tool": "http_get"},
    ])

    result = correlate_events(ev, time_window_seconds=5)
    assert result["total_events"] == 4
    assert len(result["correlations"]) == 1
    corr = result["correlations"][0]
    assert corr["agent_id"] == "a1"
    assert len(corr["events"]) == 4
    assert set(corr["sources"]) == {"messages", "transcripts", "control_plane"}
    assert corr["time_span_seconds"] == 3.0
    assert result["coverage"] == 1.0
    assert result["unmatched_messages"] == 0
    assert result["unmatched_transcripts"] == 0
    assert result["unmatched_control_plane"] == 0


def test_time_window_filtering(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:00Z"},
        {"event_id": "m2", "agent_id": "a1", "timestamp": "2026-07-08T18:01:00Z"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:02Z",
         "claimed_tool": "x", "actual_tool": "x"},
    ])
    _write_jsonl(ev / "control_plane.jsonl", [])

    result = correlate_events(ev, time_window_seconds=5)
    # m1 and c1 are within 2s -> correlated; m2 is 60s away -> separate
    groups = result["correlations"]
    multi_source = [g for g in groups if len(g["sources"]) >= 2]
    assert len(multi_source) == 1
    assert multi_source[0]["time_span_seconds"] == 2.0


def test_unmatched_events(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:00Z"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a2", "timestamp": "2026-07-08T19:00:00Z",
         "claimed_tool": "x", "actual_tool": "x"},
    ])
    _write_jsonl(ev / "control_plane.jsonl", [])

    result = correlate_events(ev, time_window_seconds=5)
    # Different agents, single events each -> no multi-source groups
    assert len(result["correlations"]) == 0
    assert result["unmatched_messages"] == 1
    assert result["unmatched_transcripts"] == 1
    assert result["coverage"] == 0.0


def test_empty_input(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    result = correlate_events(ev)
    assert result["correlations"] == []
    assert result["coverage"] == 0.0
    assert result["unmatched_messages"] == 0


def test_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        correlate_events(tmp_path / "nonexistent")


def test_multiple_agents(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:00Z"},
        {"event_id": "m2", "agent_id": "a2", "timestamp": "2026-07-08T18:00:00Z"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:01Z",
         "claimed_tool": "x", "actual_tool": "x"},
        {"call_id": "c2", "agent_id": "a2", "timestamp": "2026-07-08T18:00:01Z",
         "claimed_tool": "y", "actual_tool": "y"},
    ])
    _write_jsonl(ev / "control_plane.jsonl", [])

    result = correlate_events(ev, time_window_seconds=5)
    assert len(result["correlations"]) == 2
    agents = {c["agent_id"] for c in result["correlations"]}
    assert agents == {"a1", "a2"}
    assert result["coverage"] == 1.0


def test_format_text(tmp_path: Path) -> None:
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:00Z"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "timestamp": "2026-07-08T18:00:01Z",
         "claimed_tool": "x", "actual_tool": "x"},
    ])
    _write_jsonl(ev / "control_plane.jsonl", [])

    result = correlate_events(ev, time_window_seconds=5)
    text = format_correlate_text(result)
    assert "correlation" in text.lower()
    assert "Coverage:" in text
    assert "a1" in text


def test_no_timestamp_events(tmp_path: Path) -> None:
    """Events without timestamps are handled gracefully."""
    ev = tmp_path / "evidence"
    ev.mkdir()
    _write_jsonl(ev / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1"},
        {"event_id": "m2", "agent_id": "a1"},
    ])
    _write_jsonl(ev / "transcripts.jsonl", [])
    _write_jsonl(ev / "control_plane.jsonl", [])

    result = correlate_events(ev, time_window_seconds=5)
    # Two same-agent messages without timestamps -> grouped by agent but single-source
    assert result["total_events"] == 2
