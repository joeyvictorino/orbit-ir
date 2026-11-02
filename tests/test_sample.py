"""Tests for orbit_ir.sample."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.sample import sample_evidence, format_sample_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path, n: int = 20) -> None:
    evidence.mkdir(exist_ok=True)
    msgs = [
        {"event_id": f"m{i}", "timestamp": f"2026-07-08T18:00:{i:02d}Z",
         "agent_id": f"a{i % 3}", "recipient_agent_id": f"a{(i + 1) % 3}"}
        for i in range(n)
    ]
    _write_jsonl(evidence / "messages.jsonl", msgs)
    transcripts = [
        {"call_id": f"c{i}", "agent_id": f"a{i % 3}",
         "claimed_tool": "http_get", "actual_tool": "http_get"}
        for i in range(n // 2)
    ]
    _write_jsonl(evidence / "transcripts.jsonl", transcripts)


def test_sample_by_count(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence, n=20)
    out = tmp_path / "sampled"
    result = sample_evidence(evidence, out, count=5)
    assert result["total_output"] <= 10
    assert result["total_input"] == 30
    assert result["reduction_percent"] > 0


def test_sample_by_percent(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence, n=100)
    out = tmp_path / "sampled"
    result = sample_evidence(evidence, out, percent=10.0)
    assert result["total_output"] < result["total_input"]
    assert result["total_output"] > 0


def test_sample_stratified(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence, n=30)
    out = tmp_path / "sampled"
    result = sample_evidence(evidence, out, count=9, stratify_by="agent_id")
    assert result["total_output"] > 0
    assert result["total_output"] < result["total_input"]

    rows = []
    for f in sorted(out.glob("*.jsonl")):
        with f.open() as fp:
            for line in fp:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    agents = {r.get("agent_id") for r in rows if "agent_id" in r}
    assert len(agents) > 1


def test_sample_deterministic(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence, n=20)
    out1 = tmp_path / "s1"
    out2 = tmp_path / "s2"
    r1 = sample_evidence(evidence, out1, count=5, seed=99)
    r2 = sample_evidence(evidence, out2, count=5, seed=99)
    assert r1["total_output"] == r2["total_output"]


def test_sample_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    out = tmp_path / "sampled"
    result = sample_evidence(evidence, out)
    assert result["total_input"] == 0
    assert result["total_output"] == 0


def test_sample_not_a_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        sample_evidence(tmp_path / "nope", tmp_path / "out")


def test_format_sample_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence, n=20)
    out = tmp_path / "sampled"
    result = sample_evidence(evidence, out, count=3)
    text = format_sample_text(result)
    assert "Sample:" in text
    assert "reduction" in text
    assert "messages.jsonl" in text
