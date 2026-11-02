"""Tests for orbit_ir.chain."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.chain import ChainStep, parse_chain, run_chain, format_chain_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path) -> None:
    evidence.mkdir(exist_ok=True)
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "A1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:05Z", "agent_id": "a2"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "A1", "claimed_tool": "http_get", "actual_tool": "http_get"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "A1", "tool": "http_get"}],
    )


def test_parse_chain_basic() -> None:
    yaml_content = """
steps:
  - command: normalize
  - command: stats
    args:
      foo: bar
"""
    steps = parse_chain(yaml_content)
    assert len(steps) == 2
    assert steps[0].command == "normalize"
    assert steps[0].args == {}
    assert steps[1].command == "stats"
    assert steps[1].args == {"foo": "bar"}


def test_parse_chain_missing_steps() -> None:
    with pytest.raises(ValueError, match="must have a top-level"):
        parse_chain("foo: bar")


def test_parse_chain_empty_steps() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        parse_chain("steps: []")


def test_parse_chain_unknown_command() -> None:
    with pytest.raises(ValueError, match="unknown command"):
        parse_chain("steps:\n  - command: nonexistent")


def test_run_two_step_chain(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    work = tmp_path / "work"

    steps = [
        ChainStep(command="normalize"),
        ChainStep(command="stats"),
    ]
    result = run_chain(steps, evidence, work)
    assert result["succeeded"] == 2
    assert result["failed"] == 0
    assert result["total_steps"] == 2
    assert result["total_duration_seconds"] > 0

    step_0 = result["steps"][0]
    assert step_0["command"] == "normalize"
    assert step_0["status"] == "ok"

    step_1 = result["steps"][1]
    assert step_1["command"] == "stats"
    assert step_1["status"] == "ok"

    stats_path = work / "step_1_stats" / "stats.json"
    assert stats_path.exists()
    stats_data = json.loads(stats_path.read_text(encoding="utf-8"))
    assert stats_data["messages"] == 2


def test_run_chain_with_error(tmp_path: Path) -> None:
    work = tmp_path / "work"
    nonexistent = tmp_path / "no-such-dir"

    steps = [ChainStep(command="stats")]
    result = run_chain(steps, nonexistent, work)
    assert result["failed"] == 1
    assert result["succeeded"] == 0
    assert result["steps"][0]["status"] == "error"


def test_format_chain_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    work = tmp_path / "work"

    steps = [ChainStep(command="stats")]
    result = run_chain(steps, evidence, work)
    text = format_chain_text(result)
    assert "Pipeline:" in text
    assert "1/1 steps succeeded" in text
    assert "[OK]" in text
    assert "stats" in text


def test_run_replay_step(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    work = tmp_path / "work"

    steps = [ChainStep(command="replay")]
    result = run_chain(steps, evidence, work)
    assert result["succeeded"] == 1

    replay_path = work / "step_0_replay" / "replay.json"
    assert replay_path.exists()


def test_run_report_step(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    work = tmp_path / "work"

    steps = [ChainStep(command="report", args={"sections": "summary,findings"})]
    result = run_chain(steps, evidence, work)
    assert result["succeeded"] == 1
    assert result["steps"][0]["details"]["output_file"].endswith("report.txt")
