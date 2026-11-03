"""Tests for orbit_ir.tag."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.tag import tag_events, list_tags, filter_by_tag, format_tag_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def test_agent_tag(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
        {"event_id": "m2", "agent_id": "a2", "timestamp": "2026-01-01T00:01:00Z"},
    ])

    out = tmp_path / "output"
    result = tag_events(evidence, out, [{"agent_id": "a1", "tag": "suspicious"}])

    rows = _read_jsonl(out / "messages.jsonl")
    assert "suspicious" in rows[0].get("tags", [])
    assert "tags" not in rows[1] or "suspicious" not in rows[1].get("tags", [])
    assert result["total_tagged"] == 1


def test_tool_tag(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "shell_exec", "actual_tool": "shell_exec"},
        {"call_id": "c2", "agent_id": "a2", "claimed_tool": "http_get", "actual_tool": "http_get"},
    ])

    out = tmp_path / "output"
    result = tag_events(evidence, out, [{"tool": "shell_exec", "tag": "high_risk"}])

    rows = _read_jsonl(out / "transcripts.jsonl")
    assert "high_risk" in rows[0].get("tags", [])
    assert "tags" not in rows[1] or "high_risk" not in rows[1].get("tags", [])


def test_time_based_tag(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
        {"event_id": "m2", "agent_id": "a2", "timestamp": "2026-06-15T12:00:00Z"},
    ])

    out = tmp_path / "output"
    result = tag_events(evidence, out, [{"after": "2026-03-01T00:00:00Z", "tag": "post_incident"}])

    rows = _read_jsonl(out / "messages.jsonl")
    assert "tags" not in rows[0] or "post_incident" not in rows[0].get("tags", [])
    assert "post_incident" in rows[1].get("tags", [])


def test_list_tags(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "tags": ["suspicious", "reviewed"]},
        {"event_id": "m2", "agent_id": "a2", "tags": ["suspicious"]},
    ])

    result = list_tags(evidence)
    assert result["total_tags"]["suspicious"] == 2
    assert result["total_tags"]["reviewed"] == 1
    assert "suspicious" in result["unique_tags"]
    assert "reviewed" in result["unique_tags"]


def test_filter_by_tag(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "tags": ["suspicious"]},
        {"event_id": "m2", "agent_id": "a2", "tags": ["clean"]},
        {"event_id": "m3", "agent_id": "a3"},
    ])

    events = filter_by_tag(evidence, "suspicious")
    assert len(events) == 1
    assert events[0]["event_id"] == "m1"


def test_multiple_rules(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "shell_exec", "actual_tool": "shell_exec"},
    ])

    out = tmp_path / "output"
    result = tag_events(evidence, out, [
        {"agent_id": "a1", "tag": "suspicious"},
        {"tool": "shell_exec", "tag": "high_risk"},
    ])

    assert result["total_tagged"] >= 2
    msg_rows = _read_jsonl(out / "messages.jsonl")
    assert "suspicious" in msg_rows[0].get("tags", [])
    trans_rows = _read_jsonl(out / "transcripts.jsonl")
    assert "high_risk" in trans_rows[0].get("tags", [])
    assert "suspicious" in trans_rows[0].get("tags", [])


def test_no_duplicate_tags(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "tags": ["existing"]},
    ])

    out = tmp_path / "output"
    tag_events(evidence, out, [{"agent_id": "a1", "tag": "existing"}])

    rows = _read_jsonl(out / "messages.jsonl")
    assert rows[0]["tags"].count("existing") == 1


def test_format_tag_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
    ])

    out = tmp_path / "output"
    result = tag_events(evidence, out, [{"agent_id": "a1", "tag": "test_tag"}])
    text = format_tag_text(result)
    assert "Rules applied:" in text
    assert "test_tag" in text


def test_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        tag_events(tmp_path / "nonexistent", tmp_path / "output", [])


def test_ground_truth_copied(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
    ])
    (evidence / "ground_truth.json").write_text("{}", encoding="utf-8")

    out = tmp_path / "output"
    tag_events(evidence, out, [{"agent_id": "a1", "tag": "test"}])

    assert (out / "ground_truth.json").exists()


def test_cli_normalize_json(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "A1"},
    ])
    out = tmp_path / "output"

    args = cli.build_parser().parse_args(["normalize", "--input", str(evidence), "--output", str(out), "--format", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["total_changes"] >= 1


def test_cli_tag_rule(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    out = tmp_path / "output"

    args = cli.build_parser().parse_args([
        "tag", "--input", str(evidence), "--output", str(out),
        "--rule", "agent_id=a1:flagged", "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["total_tagged"] == 1


def test_cli_tag_list(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "tags": ["suspicious"]},
    ])

    args = cli.build_parser().parse_args(["tag", "--input", str(evidence), "--list", "--format", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert "suspicious" in data["unique_tags"]
