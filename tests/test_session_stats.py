"""Tests for the per-session statistics module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.session_stats import (
    analyze,
    format_text,
    format_json,
    SessionSummary,
    SessionStatsReport,
    _parse_ts,
    _load_events,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {"session_id": "s1", "agent_id": "agent-1", "action": "read", "resource": "/etc/config", "tool": "file_read", "timestamp": "2024-01-01T00:00:01Z"},
        {"session_id": "s1", "agent_id": "agent-1", "action": "write", "resource": "/etc/config", "tool": "file_write", "timestamp": "2024-01-01T00:00:05Z"},
        {"session_id": "s1", "agent_id": "agent-2", "action": "execute", "resource": "/usr/bin/curl", "tool": "shell", "timestamp": "2024-01-01T00:00:10Z"},
        {"session_id": "s2", "agent_id": "agent-3", "action": "read", "resource": "/data/db", "tool": "db_query", "timestamp": "2024-01-01T00:01:00Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    return tmp_path


def test_analyze_empty(empty_dir: Path) -> None:
    report = analyze(empty_dir)
    assert report.total_sessions == 0
    assert report.total_events == 0
    assert report.sessions == []


def test_analyze_basic(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    assert report.total_sessions == 2
    assert report.total_events == 4


def test_session_event_counts(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].event_count == 3
    assert by_id["s2"].event_count == 1


def test_session_agent_counts(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].agent_count == 2
    assert sorted(by_id["s1"].agents) == ["agent-1", "agent-2"]
    assert by_id["s2"].agent_count == 1


def test_session_unique_resources(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].unique_resources == 2
    assert by_id["s2"].unique_resources == 1


def test_session_unique_tools(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].unique_tools == 3
    assert by_id["s2"].unique_tools == 1


def test_session_action_types(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].action_types == {"read": 1, "write": 1, "execute": 1}
    assert by_id["s2"].action_types == {"read": 1}


def test_session_duration(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].duration_seconds == 9.0
    assert by_id["s2"].duration_seconds == 0.0


def test_session_timestamps(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert by_id["s1"].first_event != ""
    assert by_id["s1"].last_event != ""


def test_sessions_sorted_by_event_count(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    assert report.sessions[0].event_count >= report.sessions[1].event_count


def test_top_resources(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert len(by_id["s1"].top_resources) <= 5
    assert "/etc/config" in by_id["s1"].top_resources


def test_top_tools(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    by_id = {s.session_id: s for s in report.sessions}
    assert len(by_id["s1"].top_tools) <= 5


def test_format_text(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    text = format_text(report)
    assert "Session Statistics Report" in text
    assert "Total sessions:" in text
    assert "s1" in text


def test_format_json(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    output = format_json(report)
    data = json.loads(output)
    assert "total_sessions" in data
    assert "sessions" in data
    assert len(data["sessions"]) == 2


def test_parse_ts_formats() -> None:
    assert _parse_ts("2024-01-01T00:00:01.000000Z") is not None
    assert _parse_ts("2024-01-01T00:00:01Z") is not None
    assert _parse_ts("2024-01-01 00:00:01") is not None
    assert _parse_ts("not-a-timestamp") is None


def test_load_events_multiple_files(tmp_path: Path) -> None:
    (tmp_path / "events.jsonl").write_text('{"a": 1}\n', encoding="utf-8")
    (tmp_path / "transcripts.jsonl").write_text('{"b": 2}\n', encoding="utf-8")
    events = _load_events(tmp_path)
    assert len(events) == 2


def test_fallback_session_id(tmp_path: Path) -> None:
    events = [
        {"run_id": "run-1", "action": "read", "timestamp": "2024-01-01T00:00:01Z"},
        {"trace_id": "trace-1", "action": "write", "timestamp": "2024-01-01T00:00:02Z"},
        {"action": "execute", "timestamp": "2024-01-01T00:00:03Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    report = analyze(tmp_path)
    ids = {s.session_id for s in report.sessions}
    assert "run-1" in ids
    assert "trace-1" in ids
    assert "default" in ids


def test_malformed_json_lines_skipped(tmp_path: Path) -> None:
    (tmp_path / "events.jsonl").write_text(
        '{"a": 1}\nnot-json\n{"b": 2}\n', encoding="utf-8"
    )
    events = _load_events(tmp_path)
    assert len(events) == 2
