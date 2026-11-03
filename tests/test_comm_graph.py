"""Tests for orbit_ir.comm_graph."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.comm_graph import build_comm_graph, format_dot, format_summary, load_and_build


def test_build_basic() -> None:
    messages = [
        {"agent_id": "a1", "recipient_agent_id": "a2"},
        {"agent_id": "a1", "recipient_agent_id": "a2"},
        {"agent_id": "a2", "recipient_agent_id": "a3"},
    ]
    g = build_comm_graph(messages)
    assert ("a1", "a2") in g["edges"]
    assert g["edges"][("a1", "a2")] == 2
    assert g["edges"][("a2", "a3")] == 1
    assert g["nodes"] == {"a1", "a2", "a3"}


def test_build_self_loop() -> None:
    messages = [
        {"agent_id": "a1", "recipient_agent_id": "a1"},
    ]
    g = build_comm_graph(messages)
    assert g["edges"][("a1", "a1")] == 1
    assert g["nodes"] == {"a1"}


def test_build_broadcast_skipped() -> None:
    messages = [
        {"agent_id": "a1", "recipient_agent_id": None},
        {"agent_id": "a1"},
    ]
    g = build_comm_graph(messages)
    assert len(g["edges"]) == 0
    assert g["nodes"] == {"a1"}


def test_build_empty() -> None:
    g = build_comm_graph([])
    assert len(g["edges"]) == 0
    assert len(g["nodes"]) == 0


def test_format_dot_structure() -> None:
    messages = [
        {"agent_id": "a1", "recipient_agent_id": "a2"},
        {"agent_id": "a2", "recipient_agent_id": "a3"},
    ]
    g = build_comm_graph(messages)
    dot = format_dot(g)
    assert "digraph comm {" in dot
    assert '"a1"' in dot
    assert '"a2"' in dot
    assert '"a3"' in dot
    assert '"a1" -> "a2"' in dot
    assert 'label="1"' in dot
    assert dot.strip().endswith("}")


def test_format_dot_empty() -> None:
    g = build_comm_graph([])
    dot = format_dot(g)
    assert "digraph comm {" in dot
    assert dot.strip().endswith("}")


def test_format_summary() -> None:
    messages = [
        {"agent_id": "a1", "recipient_agent_id": "a2"},
        {"agent_id": "a1", "recipient_agent_id": "a2"},
        {"agent_id": "a2", "recipient_agent_id": "a1"},
    ]
    g = build_comm_graph(messages)
    s = format_summary(g)
    assert s["nodes"] == ["a1", "a2"]
    assert s["total_messages"] == 3
    assert s["total_edges"] == 2
    assert len(s["edges"]) == 2


def test_load_and_build(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with (evidence / "messages.jsonl").open("w") as f:
        f.write(json.dumps({"agent_id": "a1", "recipient_agent_id": "a2"}) + "\n")
        f.write(json.dumps({"agent_id": "a2", "recipient_agent_id": "a1"}) + "\n")
    g = load_and_build(evidence)
    assert len(g["edges"]) == 2
    assert len(g["nodes"]) == 2


def test_load_and_build_missing_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    g = load_and_build(evidence)
    assert len(g["edges"]) == 0


def test_comm_graph_cli(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli
    from orbit_ir.generator import LabConfig, generate_dataset

    data_dir = tmp_path / "evidence"
    out_dir = tmp_path / "results"
    generate_dataset(data_dir, LabConfig(seed=42, agents=20, messages=100, transcripts=30, participants=10, spoofed_tool_calls=2, unbacked_completions=2, oracle_modifications=1, lateral_accesses=1, coordinators=1))

    args = cli.build_parser().parse_args([
        "analyze",
        "--input", str(data_dir),
        "--out", str(out_dir),
        "--comm-graph",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "digraph comm {" in output

    dot_path = out_dir / "comm_graph.dot"
    assert dot_path.exists()

    summary_path = out_dir / "comm_graph.json"
    assert summary_path.exists()
    data = json.loads(summary_path.read_text())
    assert "nodes" in data
    assert "edges" in data
    assert "total_messages" in data
