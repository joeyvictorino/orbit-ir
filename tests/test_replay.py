"""Tests for orbit_ir.replay."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.replay import replay_events, format_replay_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_replay_ordering(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:05Z", "agent_id": "a1", "recipient_agent_id": "a2"},
        {"event_id": "m2", "timestamp": "2026-07-08T18:00:01Z", "agent_id": "a2", "recipient_agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "timestamp": "2026-07-08T18:00:03Z", "agent_id": "a1",
         "claimed_tool": "http_get", "actual_tool": "http_get"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    assert len(events) == 3
    # Should be sorted by timestamp.
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)
    assert events[0]["event_id"] == "m2"
    assert events[1]["call_id"] == "c1"
    assert events[2]["event_id"] == "m1"


def test_replay_annotations_first_seen(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1"},
        {"event_id": "m2", "timestamp": "2026-07-08T18:00:01Z", "agent_id": "a2"},
        {"event_id": "m3", "timestamp": "2026-07-08T18:00:02Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    # First event for a1 should have first_seen annotation.
    assert any("first_seen:a1" in ann for ann in events[0]["annotations"])
    # Second event for a2 should have first_seen.
    assert any("first_seen:a2" in ann for ann in events[1]["annotations"])
    # Third event for a1 should NOT have first_seen.
    assert not any("first_seen" in ann for ann in events[2]["annotations"])


def test_replay_annotations_tool_mismatch(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1",
         "claimed_tool": "http_get", "actual_tool": "shell_exec"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    assert len(events) == 1
    assert any("tool_mismatch" in ann for ann in events[0]["annotations"])


def test_replay_no_annotations_mode(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence, annotate=False)
    assert len(events) == 1
    assert events[0]["annotations"] == []


def test_replay_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    events = replay_events(evidence)
    assert events == []


def test_replay_time_gap_annotation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1"},
        {"event_id": "m2", "timestamp": "2026-07-08T18:05:00Z", "agent_id": "a2"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    # Second event should have a time_gap annotation (300s gap > 60s threshold).
    assert any("time_gap" in ann for ann in events[1]["annotations"])


def test_replay_text_format(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1",
         "recipient_agent_id": "a2"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    text = format_replay_text(events)
    assert "a1" in text
    assert "msg to=a2" in text
    assert "first_seen:a1" in text


def test_replay_text_no_annotations(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    events = replay_events(evidence)
    text = format_replay_text(events, show_annotations=False)
    assert "first_seen" not in text
    assert "a1" in text


def test_replay_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        replay_events(tmp_path / "nonexistent")
