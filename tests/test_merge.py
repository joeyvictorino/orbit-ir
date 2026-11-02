"""Tests for orbit_ir.merge."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.merge import merge_evidence


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_merge_non_overlapping(tmp_path: Path) -> None:
    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    dir2 = tmp_path / "ev2"
    dir2.mkdir()
    out = tmp_path / "merged"

    _write_jsonl(dir1 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(dir2 / "messages.jsonl", [
        {"event_id": "m2", "timestamp": "2026-01-01T00:01:00Z", "agent_id": "a2"},
    ])
    _write_jsonl(dir1 / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1"},
    ])
    _write_jsonl(dir2 / "transcripts.jsonl", [
        {"call_id": "c2", "agent_id": "a2"},
    ])

    result = merge_evidence([dir1, dir2], out)
    assert result["files"]["messages.jsonl"]["output_records"] == 2
    assert result["files"]["messages.jsonl"]["duplicates_removed"] == 0
    assert result["files"]["transcripts.jsonl"]["output_records"] == 2

    merged_msgs = _read_jsonl(out / "messages.jsonl")
    assert len(merged_msgs) == 2
    assert merged_msgs[0]["event_id"] == "m1"
    assert merged_msgs[1]["event_id"] == "m2"


def test_merge_deduplication(tmp_path: Path) -> None:
    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    dir2 = tmp_path / "ev2"
    dir2.mkdir()
    out = tmp_path / "merged"

    _write_jsonl(dir1 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
        {"event_id": "m2", "timestamp": "2026-01-01T00:01:00Z", "agent_id": "a2"},
    ])
    _write_jsonl(dir2 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
        {"event_id": "m3", "timestamp": "2026-01-01T00:02:00Z", "agent_id": "a3"},
    ])

    result = merge_evidence([dir1, dir2], out)
    assert result["files"]["messages.jsonl"]["total_input_records"] == 4
    assert result["files"]["messages.jsonl"]["duplicates_removed"] == 1
    assert result["files"]["messages.jsonl"]["output_records"] == 3


def test_merge_empty_directory(tmp_path: Path) -> None:
    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    dir2 = tmp_path / "ev2"
    dir2.mkdir()
    out = tmp_path / "merged"

    _write_jsonl(dir1 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    # dir2 has no files

    result = merge_evidence([dir1, dir2], out)
    assert result["files"]["messages.jsonl"]["output_records"] == 1
    assert result["files"]["transcripts.jsonl"]["output_records"] == 0


def test_merge_ground_truth(tmp_path: Path) -> None:
    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    dir2 = tmp_path / "ev2"
    dir2.mkdir()
    out = tmp_path / "merged"

    (dir1 / "ground_truth.json").write_text(
        json.dumps({"coordinators": ["c1"], "seed": 42}), encoding="utf-8"
    )
    (dir2 / "ground_truth.json").write_text(
        json.dumps({"coordinators": ["c2"], "extra_key": True}), encoding="utf-8"
    )

    result = merge_evidence([dir1, dir2], out)
    assert result["ground_truth"]["found"] is True
    assert "coordinators" in result["ground_truth"]["conflicts"]
    assert result["ground_truth"]["keys"] == 3

    merged_gt = json.loads((out / "ground_truth.json").read_text(encoding="utf-8"))
    assert "extra_key" in merged_gt
    assert "seed" in merged_gt


def test_merge_missing_input_dir(tmp_path: Path) -> None:
    import pytest

    out = tmp_path / "merged"
    with pytest.raises(FileNotFoundError):
        merge_evidence([tmp_path / "nonexistent"], out)


def test_merge_messages_sorted_by_timestamp(tmp_path: Path) -> None:
    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    dir2 = tmp_path / "ev2"
    dir2.mkdir()
    out = tmp_path / "merged"

    _write_jsonl(dir1 / "messages.jsonl", [
        {"event_id": "m3", "timestamp": "2026-01-01T00:03:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(dir2 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:01:00Z", "agent_id": "a2"},
    ])

    merge_evidence([dir1, dir2], out)
    merged = _read_jsonl(out / "messages.jsonl")
    assert merged[0]["event_id"] == "m1"
    assert merged[1]["event_id"] == "m3"


def test_merge_cli_integration(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    dir1 = tmp_path / "ev1"
    dir1.mkdir()
    out = tmp_path / "merged"

    _write_jsonl(dir1 / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])

    args = cli.build_parser().parse_args([
        "merge", "--inputs", str(dir1), "--out", str(out),
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["files"]["messages.jsonl"]["output_records"] == 1


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
