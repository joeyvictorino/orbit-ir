"""Tests for orbit_ir.audit."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.audit import audit_evidence, format_audit_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_audit_pass(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:07Z", "agent_id": "a2"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "http_get"}],
    )
    (evidence / "ground_truth.json").write_text("{}", encoding="utf-8")

    report = audit_evidence(evidence)
    assert report["passed"] is True
    assert report["agents"] == 2  # a1, a2
    assert report["total_rows"] == 4
    assert len(report["files"]) == 4  # 3 required + 1 optional
    assert all(f["present"] for f in report["files"])
    assert all(f["sha256"] is not None for f in report["files"])


def test_audit_fail_missing_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )

    report = audit_evidence(evidence)
    assert report["passed"] is False
    missing = [f for f in report["files"] if not f["present"]]
    assert len(missing) >= 2  # transcripts and control_plane


def test_audit_fail_inconsistent_agents(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [{"call_id": "c1", "agent_id": "a999", "claimed_tool": "x", "actual_tool": "x"}],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "x"}],
    )

    report = audit_evidence(evidence)
    assert report["passed"] is False
    failed_checks = [c for c in report["checks"] if not c["passed"]]
    assert any("transcript_agents_in_messages" in c["check"] for c in failed_checks)


def test_audit_empty_dir(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    report = audit_evidence(evidence)
    assert report["passed"] is False
    assert report["agents"] == 0
    assert report["total_rows"] == 0


def test_audit_not_a_directory(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        audit_evidence(tmp_path / "nonexistent")


def test_audit_duplicate_message_ids(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
            {"event_id": "m1", "timestamp": "2026-01-01T00:00:01Z", "agent_id": "a1"},
        ],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [{"call_id": "c1", "agent_id": "a1", "claimed_tool": "x", "actual_tool": "x"}])
    _write_jsonl(evidence / "control_plane.jsonl", [{"event_id": "cp1", "agent_id": "a1", "tool": "x"}])

    report = audit_evidence(evidence)
    assert report["passed"] is False
    failed_checks = [c for c in report["checks"] if not c["passed"]]
    assert any("message_ids_unique" in c["check"] for c in failed_checks)


def test_format_audit_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [{"call_id": "c1", "agent_id": "a1", "claimed_tool": "x", "actual_tool": "x"}])
    _write_jsonl(evidence / "control_plane.jsonl", [{"event_id": "cp1", "agent_id": "a1", "tool": "x"}])

    report = audit_evidence(evidence)
    text = format_audit_text(report)
    assert "Audit:" in text
    assert "Verdict: PASS" in text
    assert "sha256=" in text


def test_audit_cli_json(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [{"call_id": "c1", "agent_id": "a1", "claimed_tool": "x", "actual_tool": "x"}])
    _write_jsonl(evidence / "control_plane.jsonl", [{"event_id": "cp1", "agent_id": "a1", "tool": "x"}])

    args = cli.build_parser().parse_args(["audit", "--input", str(evidence), "--format", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["passed"] is True
    assert data["agents"] == 1


def test_audit_cli_text(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"}],
    )
    _write_jsonl(evidence / "transcripts.jsonl", [{"call_id": "c1", "agent_id": "a1", "claimed_tool": "x", "actual_tool": "x"}])
    _write_jsonl(evidence / "control_plane.jsonl", [{"event_id": "cp1", "agent_id": "a1", "tool": "x"}])

    args = cli.build_parser().parse_args(["audit", "--input", str(evidence), "--format", "text"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "Audit:" in output
    assert "Verdict: PASS" in output
