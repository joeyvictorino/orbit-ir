"""Tests for orbit_ir.heatmap."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.heatmap import build_heatmap, format_heatmap_summary, load_and_build_heatmap


def test_build_basic() -> None:
    messages = [
        {"agent_id": "a1", "timestamp": "2026-06-01T10:05:00Z"},
        {"agent_id": "a1", "timestamp": "2026-06-01T10:30:00Z"},
        {"agent_id": "a2", "timestamp": "2026-06-01T10:15:00Z"},
        {"agent_id": "a1", "timestamp": "2026-06-01T11:05:00Z"},
    ]
    h = build_heatmap(messages, bucket_minutes=60)
    assert h["agents"] == ["a1", "a2"]
    assert len(h["buckets"]) == 2
    assert h["cells"][("a1", "2026-06-01T10:00:00Z")] == 2
    assert h["cells"][("a2", "2026-06-01T10:00:00Z")] == 1
    assert h["cells"][("a1", "2026-06-01T11:00:00Z")] == 1


def test_build_small_buckets() -> None:
    messages = [
        {"agent_id": "a1", "timestamp": "2026-06-01T10:03:00Z"},
        {"agent_id": "a1", "timestamp": "2026-06-01T10:07:00Z"},
        {"agent_id": "a1", "timestamp": "2026-06-01T10:14:00Z"},
    ]
    h = build_heatmap(messages, bucket_minutes=10)
    assert h["cells"][("a1", "2026-06-01T10:00:00Z")] == 2
    assert h["cells"][("a1", "2026-06-01T10:10:00Z")] == 1


def test_build_empty() -> None:
    h = build_heatmap([])
    assert len(h["agents"]) == 0
    assert len(h["buckets"]) == 0
    assert len(h["cells"]) == 0


def test_build_missing_fields() -> None:
    messages = [
        {"agent_id": "a1"},
        {"timestamp": "2026-06-01T10:00:00Z"},
        {},
    ]
    h = build_heatmap(messages)
    assert len(h["cells"]) == 0


def test_format_summary() -> None:
    messages = [
        {"agent_id": "a1", "timestamp": "2026-06-01T10:05:00Z"},
        {"agent_id": "a1", "timestamp": "2026-06-01T10:30:00Z"},
        {"agent_id": "a2", "timestamp": "2026-06-01T10:15:00Z"},
    ]
    h = build_heatmap(messages, bucket_minutes=60)
    s = format_heatmap_summary(h)
    assert s["total_messages"] == 3
    assert s["peak_agent"] == "a1"
    assert s["peak_agent_count"] == 2
    assert s["peak_bucket"] == "2026-06-01T10:00:00Z"
    assert s["peak_bucket_count"] == 3
    assert len(s["cells"]) == 2
    assert s["agent_totals"]["a1"] == 2
    assert s["bucket_totals"]["2026-06-01T10:00:00Z"] == 3


def test_format_summary_empty() -> None:
    h = build_heatmap([])
    s = format_heatmap_summary(h)
    assert s["total_messages"] == 0
    assert s["peak_agent"] is None
    assert s["peak_bucket"] is None


def test_load_and_build(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with (evidence / "messages.jsonl").open("w") as f:
        f.write(json.dumps({"agent_id": "a1", "timestamp": "2026-06-01T10:05:00Z"}) + "\n")
        f.write(json.dumps({"agent_id": "a2", "timestamp": "2026-06-01T10:30:00Z"}) + "\n")
    h = load_and_build_heatmap(evidence)
    assert len(h["cells"]) == 2
    assert len(h["agents"]) == 2


def test_load_missing_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    h = load_and_build_heatmap(evidence)
    assert len(h["cells"]) == 0


def test_heatmap_cli(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli
    from orbit_ir.generator import LabConfig, generate_dataset

    data_dir = tmp_path / "evidence"
    out_dir = tmp_path / "results"
    generate_dataset(
        data_dir,
        LabConfig(
            seed=42, agents=20, messages=100, transcripts=30, participants=10,
            spoofed_tool_calls=2, unbacked_completions=2,
            oracle_modifications=1, lateral_accesses=1, coordinators=1,
        ),
    )

    args = cli.build_parser().parse_args([
        "analyze",
        "--input", str(data_dir),
        "--out", str(out_dir),
        "--heatmap",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)

    heatmap_path = out_dir / "heatmap.json"
    assert heatmap_path.exists()
    data = json.loads(heatmap_path.read_text())
    assert "agents" in data
    assert "cells" in data
    assert "total_messages" in data
    assert "peak_agent" in data
