"""Tests for orbit_ir.normalize."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.normalize import normalize_evidence, format_normalize_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def test_timestamp_normalization(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-15 10:30:00", "agent_id": "a1"},
        {"event_id": "m2", "timestamp": "2026-01-15T10:30:00Z", "agent_id": "a2"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    rows = _read_jsonl(out / "messages.jsonl")
    assert rows[0]["timestamp"] == "2026-01-15T10:30:00Z"
    assert rows[1]["timestamp"] == "2026-01-15T10:30:00Z"
    assert result["total_changes"] >= 1


def test_agent_id_lowercasing(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "Agent_A", "recipient_agent_id": "Agent_B"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    rows = _read_jsonl(out / "messages.jsonl")
    assert rows[0]["agent_id"] == "agent_a"
    assert rows[0]["recipient_agent_id"] == "agent_b"
    assert result["total_changes"] >= 2


def test_custom_renames(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "src_agent": "a1"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out, renames={"src_agent": "agent_id"})

    rows = _read_jsonl(out / "messages.jsonl")
    assert "agent_id" in rows[0]
    assert "src_agent" not in rows[0]
    assert rows[0]["agent_id"] == "a1"
    assert "src_agent" in result["renames_applied"]


def test_idempotent(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])

    out1 = tmp_path / "out1"
    normalize_evidence(evidence, out1)

    out2 = tmp_path / "out2"
    result2 = normalize_evidence(out1, out2)

    assert result2["total_changes"] == 0
    rows1 = _read_jsonl(out1 / "messages.jsonl")
    rows2 = _read_jsonl(out2 / "messages.jsonl")
    assert rows1 == rows2


def test_preserves_valid_data(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "content": "hello world"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    rows = _read_jsonl(out / "messages.jsonl")
    assert rows[0]["event_id"] == "m1"
    assert rows[0]["content"] == "hello world"
    assert result["total_changes"] == 0


def test_whitespace_normalization(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "content": "hello   world   foo"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    rows = _read_jsonl(out / "messages.jsonl")
    assert rows[0]["content"] == "hello world foo"
    assert result["total_changes"] >= 1


def test_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        normalize_evidence(tmp_path / "nonexistent", tmp_path / "output")


def test_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    assert result["total_changes"] == 0
    assert result["files"] == []


def test_format_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "A1"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)
    text = format_normalize_text(result)
    assert "Total changes:" in text
    assert "messages.jsonl" in text


def test_multiple_evidence_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "A1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "B2", "claimed_tool": "http_get", "actual_tool": "http_get"},
    ])

    out = tmp_path / "output"
    result = normalize_evidence(evidence, out)

    assert len(result["files"]) == 2
    msgs = _read_jsonl(out / "messages.jsonl")
    assert msgs[0]["agent_id"] == "a1"
    trans = _read_jsonl(out / "transcripts.jsonl")
    assert trans[0]["agent_id"] == "b2"


def test_ground_truth_copied(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    (evidence / "ground_truth.json").write_text("{}", encoding="utf-8")

    out = tmp_path / "output"
    normalize_evidence(evidence, out)

    assert (out / "ground_truth.json").exists()
