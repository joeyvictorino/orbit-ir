"""Tests for orbit_ir.timeline."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.timeline import build_timeline, format_json, format_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def test_build_timeline_merges_sources(tmp_path: Path) -> None:
    _write_jsonl(tmp_path / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-09-03T10:00:02Z", "agent_id": "a1",
         "channel": "task", "message_type": "report", "recipient_agent_id": "a2"},
    ])
    _write_jsonl(tmp_path / "transcripts.jsonl", [
        {"run_id": "r1", "timestamp": "2026-09-03T10:00:01Z", "agent_id": "a1",
         "trace_id": "t1", "tool_call_id": "tc1", "claimed_tool": "http_get",
         "claimed_args_digest": "abc"},
    ])
    _write_jsonl(tmp_path / "control_plane.jsonl", [
        {"timestamp": "2026-09-03T10:00:03Z", "agent_id": "a1", "trace_id": "t1",
         "tool_call_id": "tc1", "actual_tool": "http_get",
         "actual_args_digest": "abc", "credential_id": "c1",
         "resource": "api.example.com", "effect": "allow",
         "policy_decision": "ALLOW_RULE:r1"},
    ])

    events = build_timeline(tmp_path)
    assert len(events) == 3
    # Sorted by timestamp
    assert events[0]["source"] == "transcripts"
    assert events[1]["source"] == "messages"
    assert events[2]["source"] == "control_plane"


def test_build_timeline_empty(tmp_path: Path) -> None:
    events = build_timeline(tmp_path)
    assert events == []


def test_build_timeline_single_source(tmp_path: Path) -> None:
    _write_jsonl(tmp_path / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-09-03T10:00:00Z", "agent_id": "a1",
         "channel": "task", "message_type": "report"},
        {"event_id": "m2", "timestamp": "2026-09-03T09:00:00Z", "agent_id": "a2",
         "channel": "task", "message_type": "assignment"},
    ])
    events = build_timeline(tmp_path)
    assert len(events) == 2
    assert events[0]["agent_id"] == "a2"  # earlier timestamp first
    assert events[1]["agent_id"] == "a1"


def test_format_text_output(tmp_path: Path) -> None:
    _write_jsonl(tmp_path / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-09-03T10:00:00Z", "agent_id": "agent-007",
         "channel": "board", "message_type": "assignment", "recipient_agent_id": "agent-008"},
    ])
    events = build_timeline(tmp_path)
    text = format_text(events)
    assert "agent-007" in text
    assert "assignment" in text
    assert "agent-008" in text
    assert "messages" in text


def test_format_json_output(tmp_path: Path) -> None:
    _write_jsonl(tmp_path / "transcripts.jsonl", [
        {"run_id": "r1", "timestamp": "2026-09-03T10:00:00Z", "agent_id": "a1",
         "trace_id": "t1", "tool_call_id": "tc1", "claimed_tool": "http_get",
         "claimed_args_digest": "abc"},
    ])
    events = build_timeline(tmp_path)
    output = format_json(events)
    parsed = json.loads(output)
    assert len(parsed) == 1
    assert parsed[0]["source"] == "transcripts"
    assert parsed[0]["claimed_tool"] == "http_get"


def test_format_text_empty() -> None:
    assert format_text([]) == ""


def test_timeline_cli(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli
    from orbit_ir.generator import LabConfig, generate_dataset

    data_dir = tmp_path / "evidence"
    generate_dataset(data_dir, LabConfig(
        seed=42, agents=10, messages=50, transcripts=20,
        participants=5, spoofed_tool_calls=1, unbacked_completions=1,
        oracle_modifications=1, lateral_accesses=1, coordinators=1,
    ))

    # Text format
    args = cli.build_parser().parse_args([
        "timeline", "--input", str(data_dir),
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    text = buf.getvalue()
    assert "messages" in text or "transcripts" in text or "control_plane" in text

    # JSON format
    args = cli.build_parser().parse_args([
        "timeline", "--input", str(data_dir), "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    parsed = json.loads(buf.getvalue())
    assert isinstance(parsed, list)
    assert len(parsed) > 0

    # Source filter
    args = cli.build_parser().parse_args([
        "timeline", "--input", str(data_dir), "--source", "messages", "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    filtered = json.loads(buf.getvalue())
    assert all(e["source"] == "messages" for e in filtered)

    # Agent filter
    first_agent = parsed[0]["agent_id"]
    args = cli.build_parser().parse_args([
        "timeline", "--input", str(data_dir), "--agent", first_agent, "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    agent_events = json.loads(buf.getvalue())
    assert all(e["agent_id"] == first_agent for e in agent_events)
