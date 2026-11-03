"""Tests for orbit_ir.scope."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.scope import apply_scope


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _setup_evidence(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1"},
        {"event_id": "m2", "timestamp": "2026-07-08T19:00:00Z", "agent_id": "a2"},
        {"event_id": "m3", "timestamp": "2026-07-08T20:00:00Z", "agent_id": "a3"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "timestamp": "2026-07-08T18:30:00Z", "agent_id": "a1", "claimed_tool": "t1", "actual_tool": "t1"},
        {"call_id": "c2", "timestamp": "2026-07-08T19:30:00Z", "agent_id": "a2", "claimed_tool": "t2", "actual_tool": "t2"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [
        {"event_id": "cp1", "timestamp": "2026-07-08T18:00:05Z", "agent_id": "a1", "tool": "t1"},
        {"event_id": "cp2", "timestamp": "2026-07-08T19:00:05Z", "agent_id": "a2", "tool": "t2"},
    ])
    return evidence


def test_scope_no_filters(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(evidence, out)
    assert result["total_before"] == 7
    assert result["total_after"] == 7
    assert result["filters_applied"] == []
    assert (out / "messages.jsonl").exists()
    assert (out / "transcripts.jsonl").exists()
    assert (out / "control_plane.jsonl").exists()


def test_scope_time_window(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(
        evidence, out,
        start="2026-07-08T18:30:00Z",
        end="2026-07-08T19:30:00Z",
    )
    assert result["total_after"] < result["total_before"]
    msgs = [json.loads(l) for l in (out / "messages.jsonl").read_text().strip().split("\n") if l.strip()]
    assert len(msgs) == 1
    assert msgs[0]["event_id"] == "m2"


def test_scope_agents(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(evidence, out, agents=["a1"])
    msgs = [json.loads(l) for l in (out / "messages.jsonl").read_text().strip().split("\n") if l.strip()]
    assert len(msgs) == 1
    assert msgs[0]["agent_id"] == "a1"
    assert "agents=a1" in result["filters_applied"]


def test_scope_sources(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(evidence, out, sources=["messages"])
    msgs_content = (out / "messages.jsonl").read_text()
    assert len(msgs_content.strip().split("\n")) == 3
    assert result["files"]["transcripts"].get("skipped") is True
    assert result["files"]["control_plane"].get("skipped") is True


def test_scope_combined_filters(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(
        evidence, out,
        start="2026-07-08T18:00:00Z",
        end="2026-07-08T19:00:00Z",
        agents=["a1"],
        sources=["messages", "control_plane"],
    )
    msgs = [json.loads(l) for l in (out / "messages.jsonl").read_text().strip().split("\n") if l.strip()]
    assert len(msgs) == 1
    assert msgs[0]["agent_id"] == "a1"
    assert result["files"]["transcripts"].get("skipped") is True
    assert len(result["filters_applied"]) == 4


def test_scope_empty_result(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    result = apply_scope(evidence, out, agents=["nonexistent"])
    assert result["total_after"] == 0
    content = (out / "messages.jsonl").read_text()
    assert content == ""


def test_scope_copies_ground_truth(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    gt = {"coordinators": ["a1"]}
    (evidence / "ground_truth.json").write_text(json.dumps(gt), encoding="utf-8")
    out = tmp_path / "scoped"
    apply_scope(evidence, out)
    assert (out / "ground_truth.json").exists()
    loaded = json.loads((out / "ground_truth.json").read_text())
    assert loaded == gt


def test_scope_missing_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        apply_scope(tmp_path / "nope", tmp_path / "out")


def test_scope_cli(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = _setup_evidence(tmp_path)
    out = tmp_path / "scoped"
    args = cli.build_parser().parse_args([
        "scope", "--input", str(evidence), "--out", str(out),
        "--agents", "a1,a2", "--start", "2026-07-08T18:00:00Z",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    result = json.loads(buf.getvalue())
    assert result["total_after"] <= result["total_before"]
    assert "agents=a1,a2" in result["filters_applied"]
