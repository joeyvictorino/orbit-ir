"""Tests for orbit_ir.fingerprint."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.fingerprint import fingerprint_agents, format_fingerprint_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_fingerprint_basic(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-01-01T00:01:00Z", "agent_id": "a1", "recipient_agent_id": "a3"},
            {"event_id": "m3", "timestamp": "2026-01-01T00:02:00Z", "agent_id": "a2", "recipient_agent_id": "a1"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
            {"call_id": "c2", "agent_id": "a1", "claimed_tool": "http_post", "actual_tool": "http_post"},
            {"call_id": "c3", "agent_id": "a2", "claimed_tool": "shell_exec", "actual_tool": "shell_exec"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "http_get"}],
    )

    result = fingerprint_agents(evidence)
    assert result["agent_count"] == 3

    a1 = result["profiles"]["a1"]
    assert a1["messages_sent"] == 2
    assert a1["unique_recipients"] == 2
    assert a1["tool_calls"] == 2
    assert a1["unique_tools"] == 2
    assert a1["tool_mismatch_rate"] == 0.0
    assert a1["control_plane_events"] == 1

    a2 = result["profiles"]["a2"]
    assert a2["messages_sent"] == 1

    a3 = result["profiles"]["a3"]
    assert a3["messages_sent"] == 0


def test_fingerprint_tool_mismatches(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(evidence / "messages.jsonl", [])
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "shell_exec"},
            {"call_id": "c2", "agent_id": "a1", "claimed_tool": "http_post", "actual_tool": "http_post"},
            {"call_id": "c3", "agent_id": "a2", "claimed_tool": "http_get", "actual_tool": "http_get"},
        ],
    )

    result = fingerprint_agents(evidence)
    a1 = result["profiles"]["a1"]
    assert a1["tool_mismatch_rate"] == 0.5


def test_fingerprint_anomaly_scores(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    msgs = []
    for i in range(50):
        msgs.append({"event_id": f"m{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z", "agent_id": "a1"})
    msgs.append({"event_id": "m99", "timestamp": "2026-01-01T01:00:00Z", "agent_id": "a2"})
    msgs.append({"event_id": "m100", "timestamp": "2026-01-01T01:01:00Z", "agent_id": "a3"})
    _write_jsonl(evidence / "messages.jsonl", msgs)

    result = fingerprint_agents(evidence)
    a1 = result["profiles"]["a1"]
    assert a1["anomaly_score"] > 1.0


def test_fingerprint_empty_dir(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    result = fingerprint_agents(evidence)
    assert result["agent_count"] == 0
    assert result["profiles"] == {}


def test_fingerprint_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        fingerprint_agents(tmp_path / "nonexistent")


def test_format_fingerprint_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
            {"event_id": "m2", "timestamp": "2026-01-01T00:01:00Z", "agent_id": "a2"},
        ],
    )
    result = fingerprint_agents(evidence)
    text = format_fingerprint_text(result)
    assert "a1" in text
    assert "a2" in text
    assert "fingerprints" in text.lower()
