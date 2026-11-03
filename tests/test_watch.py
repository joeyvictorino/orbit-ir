"""Tests for orbit_ir.watch."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.watch import snapshot_evidence, diff_snapshots, format_diff_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_snapshot_captures_state(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "agent_id": "a1"},
            {"event_id": "m2", "agent_id": "a2"},
        ],
    )

    snap = snapshot_evidence(evidence)
    assert snap["evidence_files"]["messages.jsonl"]["lines"] == 2
    assert snap["evidence_files"]["messages.jsonl"]["size"] > 0
    assert snap["evidence_files"]["transcripts.jsonl"].get("missing") is True
    assert "messages.jsonl" in snap["all_files"]
    assert snap["timestamp"] > 0


def test_snapshot_empty_dir(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    snap = snapshot_evidence(evidence)
    for name in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl"):
        assert snap["evidence_files"][name].get("missing") is True
        assert snap["evidence_files"][name]["lines"] == 0


def test_snapshot_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        snapshot_evidence(tmp_path / "nonexistent")


def test_diff_detects_changes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [{"event_id": "m1", "agent_id": "a1"}])

    before = snapshot_evidence(evidence)

    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "agent_id": "a1"},
            {"event_id": "m2", "agent_id": "a2"},
        ],
    )

    after = snapshot_evidence(evidence)
    d = diff_snapshots(before, after)

    assert d["changed"] is True
    assert len(d["changes"]) == 1
    assert d["changes"][0]["file"] == "messages.jsonl"
    assert d["changes"][0]["change"] == "modified"
    assert d["changes"][0]["lines_added"] == 1


def test_diff_detects_no_changes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [{"event_id": "m1", "agent_id": "a1"}])

    snap = snapshot_evidence(evidence)
    d = diff_snapshots(snap, snap)

    assert d["changed"] is False
    assert len(d["changes"]) == 0


def test_diff_detects_new_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    before = snapshot_evidence(evidence)

    _write_jsonl(evidence / "messages.jsonl", [{"event_id": "m1", "agent_id": "a1"}])

    after = snapshot_evidence(evidence)
    d = diff_snapshots(before, after)

    assert d["changed"] is True
    assert any(c["change"] == "created" for c in d["changes"])


def test_diff_detects_removed_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    msg_path = evidence / "messages.jsonl"
    _write_jsonl(msg_path, [{"event_id": "m1", "agent_id": "a1"}])

    before = snapshot_evidence(evidence)

    msg_path.unlink()

    after = snapshot_evidence(evidence)
    d = diff_snapshots(before, after)

    assert d["changed"] is True
    assert any(c["change"] == "removed" for c in d["changes"])


def test_format_diff_text_no_changes(tmp_path: Path) -> None:
    d = {"changed": False, "changes": [], "new_files": [], "removed_files": []}
    text = format_diff_text(d)
    assert "No changes" in text


def test_format_diff_text_with_changes(tmp_path: Path) -> None:
    d = {
        "changed": True,
        "changes": [
            {"file": "messages.jsonl", "change": "modified", "lines_before": 1, "lines_after": 3, "lines_added": 2, "size_diff": 100},
        ],
        "new_files": [],
        "removed_files": [],
    }
    text = format_diff_text(d)
    assert "messages.jsonl" in text
    assert "+2" in text


def test_watch_cli_parser() -> None:
    from orbit_ir import cli
    parser = cli.build_parser()
    args = parser.parse_args(["watch", "--input", "/tmp/ev", "--interval", "5"])
    assert args.command == "watch"
    assert args.interval == 5.0
