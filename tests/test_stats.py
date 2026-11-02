"""Tests for orbit_ir.stats."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.stats import evidence_stats, format_stats_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_evidence_stats_basic(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:07Z", "agent_id": "a2", "recipient_agent_id": None},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
            {"call_id": "c2", "agent_id": "a3", "claimed_tool": "http_post", "actual_tool": "http_post"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "http_get"}],
    )
    (evidence / "ground_truth.json").write_text("{}", encoding="utf-8")

    s = evidence_stats(evidence)
    assert s["agents"] == 3  # a1, a2, a3
    assert s["messages"] == 2
    assert s["transcripts"] == 2
    assert s["control_plane_events"] == 1
    assert sorted(s["unique_tools"]) == ["http_get", "http_post"]
    assert s["time_range"]["earliest"] == "2026-07-08T18:00:00Z"
    assert s["time_range"]["latest"] == "2026-07-08T18:00:07Z"
    assert s["has_ground_truth"] is True
    assert len(s["files"]) == 3
    assert all(f["present"] for f in s["files"])


def test_evidence_stats_missing_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [{"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"}])

    s = evidence_stats(evidence)
    assert s["messages"] == 1
    assert s["transcripts"] == 0
    assert s["control_plane_events"] == 0
    assert s["has_ground_truth"] is False
    missing = [f for f in s["files"] if not f["present"]]
    assert len(missing) == 2


def test_evidence_stats_empty_dir(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    s = evidence_stats(evidence)
    assert s["agents"] == 0
    assert s["messages"] == 0
    assert s["time_range"] == {}


def test_format_stats_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [{"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"}])
    s = evidence_stats(evidence)
    text = format_stats_text(s)
    assert "Agents:" in text
    assert "Messages:" in text
    assert "1" in text


def test_stats_not_a_directory(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        evidence_stats(tmp_path / "nonexistent")


def test_stats_cli_json(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    args = cli.build_parser().parse_args(["stats", "--input", str(evidence), "--format", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["agents"] == 1
    assert data["messages"] == 1


def test_stats_cli_text(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    args = cli.build_parser().parse_args(["stats", "--input", str(evidence), "--format", "text"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "Agents:" in output
    assert "Messages:" in output
