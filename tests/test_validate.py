"""Tests for evidence format validation."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.validate import validate_evidence


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def _make_evidence(tmp_path: Path) -> Path:
    d = tmp_path / "evidence"
    d.mkdir()
    _write_jsonl(d / "messages.jsonl", [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "agent_id": "a1", "channel": "chat", "message_type": "text"},
    ])
    _write_jsonl(d / "transcripts.jsonl", [
        {"run_id": "r1", "timestamp": "2026-01-01T00:00:01Z",
         "agent_id": "a1", "trace_id": "t1", "tool_call_id": "tc1",
         "claimed_tool": "read", "claimed_args_digest": "abc"},
    ])
    _write_jsonl(d / "control_plane.jsonl", [
        {"timestamp": "2026-01-01T00:00:01Z", "agent_id": "a1",
         "trace_id": "t1", "tool_call_id": "tc1", "actual_tool": "read",
         "actual_args_digest": "abc", "credential_id": "c1",
         "resource": "/data", "effect": "read", "policy_decision": "allow"},
    ])
    return d


def test_valid_evidence(tmp_path):
    d = _make_evidence(tmp_path)
    report = validate_evidence(d)
    assert report["valid"] is True
    assert report["summary"]["total_errors"] == 0
    for fname in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl"):
        assert report["files"][fname]["records"] == 1


def test_missing_file(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    _write_jsonl(d / "messages.jsonl", [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "agent_id": "a1", "channel": "chat", "message_type": "text"},
    ])
    _write_jsonl(d / "transcripts.jsonl", [
        {"run_id": "r1", "timestamp": "2026-01-01T00:00:01Z",
         "agent_id": "a1", "trace_id": "t1", "tool_call_id": "tc1",
         "claimed_tool": "read", "claimed_args_digest": "abc"},
    ])
    report = validate_evidence(d)
    assert report["valid"] is False
    assert "file not found" in report["files"]["control_plane.jsonl"]["errors"][0]


def test_bad_json(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "messages.jsonl").write_text("{bad json\n", encoding="utf-8")
    _write_jsonl(d / "transcripts.jsonl", [])
    _write_jsonl(d / "control_plane.jsonl", [])
    report = validate_evidence(d)
    assert report["valid"] is False
    assert any("invalid JSON" in e for e in report["files"]["messages.jsonl"]["errors"])


def test_missing_fields(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    _write_jsonl(d / "messages.jsonl", [{"event_id": "e1"}])
    _write_jsonl(d / "transcripts.jsonl", [])
    _write_jsonl(d / "control_plane.jsonl", [])
    report = validate_evidence(d)
    assert report["valid"] is False
    assert any("missing fields" in e for e in report["files"]["messages.jsonl"]["errors"])


def test_bad_timestamp(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    _write_jsonl(d / "messages.jsonl", [
        {"event_id": "e1", "timestamp": "not-a-date",
         "agent_id": "a1", "channel": "chat", "message_type": "text"},
    ])
    _write_jsonl(d / "transcripts.jsonl", [])
    _write_jsonl(d / "control_plane.jsonl", [])
    report = validate_evidence(d)
    assert report["valid"] is False
    assert any("timestamp" in e.lower() for e in report["files"]["messages.jsonl"]["errors"])


def test_integrity_tool_call_alignment(tmp_path):
    d = _make_evidence(tmp_path)
    report = validate_evidence(d)
    checks = {c["name"]: c for c in report["integrity"]["checks"]}
    assert checks["tool_call_id_alignment"]["matched"] == 1


def test_integrity_no_overlap(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    _write_jsonl(d / "messages.jsonl", [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "agent_id": "a1", "channel": "chat", "message_type": "text"},
    ])
    _write_jsonl(d / "transcripts.jsonl", [
        {"run_id": "r1", "timestamp": "2026-01-01T00:00:01Z",
         "agent_id": "a1", "trace_id": "t1", "tool_call_id": "tc-AAA",
         "claimed_tool": "read", "claimed_args_digest": "abc"},
    ])
    _write_jsonl(d / "control_plane.jsonl", [
        {"timestamp": "2026-01-01T00:00:01Z", "agent_id": "a1",
         "trace_id": "t1", "tool_call_id": "tc-BBB", "actual_tool": "read",
         "actual_args_digest": "abc", "credential_id": "c1",
         "resource": "/data", "effect": "read", "policy_decision": "allow"},
    ])
    report = validate_evidence(d)
    assert report["valid"] is False
    assert any("No tool_call_id matches" in e for e in report["integrity"]["errors"])


def test_json_output_format(tmp_path):
    d = _make_evidence(tmp_path)
    report = validate_evidence(d)
    text = json.dumps(report)
    parsed = json.loads(text)
    assert parsed["valid"] is True
