"""Tests for orbit_ir.compare_agents."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.compare_agents import compare_agents, format_comparison_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-01-01T00:00:05Z", "agent_id": "a2", "recipient_agent_id": "a1"},
            {"event_id": "m3", "timestamp": "2026-01-01T00:00:10Z", "agent_id": "a1", "recipient_agent_id": "a3"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
            {"call_id": "c2", "agent_id": "a1", "claimed_tool": "http_post", "actual_tool": "http_post"},
            {"call_id": "c3", "agent_id": "a2", "claimed_tool": "http_get", "actual_tool": "shell_exec"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [
            {"event_id": "cp1", "agent_id": "a1", "tool": "http_get"},
        ],
    )


def test_compare_basic(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    result = compare_agents(evidence, "a1", "a2")
    assert result["agent_a"]["agent_id"] == "a1"
    assert result["agent_b"]["agent_id"] == "a2"
    assert result["agent_a"]["messages_sent"] == 2
    assert result["agent_b"]["messages_sent"] == 1
    assert result["agent_a"]["transcript_calls"] == 2
    assert result["agent_b"]["transcript_calls"] == 1
    assert result["agent_b"]["tool_mismatches"] == 1
    assert result["agent_a"]["tool_mismatches"] == 0


def test_compare_differences(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    result = compare_agents(evidence, "a1", "a2")
    metrics = {d["metric"] for d in result["differences"] if "metric" in d}
    assert "messages_sent" in metrics
    assert "transcript_calls" in metrics
    assert "tool_mismatches" in metrics


def test_compare_shared_contacts(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    result = compare_agents(evidence, "a1", "a2")
    # a1 contacts: a2, a3; a2 contacts: a1
    # shared = {a1} ∩ ... hmm let me think
    # a1's contacts: a2 (sent to), a3 (sent to), a2 (received from)
    # a2's contacts: a1 (sent to), a1 (received from)
    # shared: a1 is in a2's contacts, but a1 is agent_a, not a contact of itself
    # Actually contacts_a = {a2, a3}, contacts_b = {a1}
    # shared = {} (empty intersection)
    assert result["shared_contacts"] == []


def test_compare_agent_not_found(tmp_path: Path) -> None:
    import pytest

    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    with pytest.raises(ValueError, match="not found"):
        compare_agents(evidence, "a1", "nonexistent")


def test_compare_not_a_directory(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        compare_agents(tmp_path / "nonexistent", "a1", "a2")


def test_compare_tools_only_in_one(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    result = compare_agents(evidence, "a1", "a2")
    tool_diffs = [d for d in result["differences"] if d.get("metric", "").startswith("tools_only")]
    # a1 has http_get and http_post; a2 has http_get
    # tools_only_in_a should contain http_post
    only_a = [d for d in tool_diffs if d["metric"] == "tools_only_in_a"]
    assert len(only_a) == 1
    assert "http_post" in only_a[0]["tools"]


def test_format_comparison_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    result = compare_agents(evidence, "a1", "a2")
    text = format_comparison_text(result)
    assert "Agent Comparison:" in text
    assert "a1" in text
    assert "a2" in text
    assert "Messages sent" in text
    assert "Differences:" in text


def test_compare_cli_json(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    args = cli.build_parser().parse_args([
        "compare", "--input", str(evidence),
        "--agent-a", "a1", "--agent-b", "a2",
        "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["agent_a"]["agent_id"] == "a1"
    assert data["agent_b"]["agent_id"] == "a2"


def test_compare_cli_text(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    _make_evidence(evidence)

    args = cli.build_parser().parse_args([
        "compare", "--input", str(evidence),
        "--agent-a", "a1", "--agent-b", "a2",
        "--format", "text",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "Agent Comparison:" in output
