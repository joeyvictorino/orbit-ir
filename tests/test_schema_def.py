"""Tests for orbit_ir.schema_def."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.schema_def import (
    EVIDENCE_SCHEMAS,
    format_schema_text,
    format_validation_text,
    validate_evidence_schema,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_valid_evidence_passes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "t1", "actual_tool": "t1"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [
        {"event_id": "cp1", "agent_id": "a1", "tool": "t1"},
    ])
    issues = validate_evidence_schema(evidence)
    errors = [i for i in issues if i["severity"] == "error"]
    assert len(errors) == 0


def test_missing_required_field(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z"},
    ])
    issues = validate_evidence_schema(evidence)
    errors = [i for i in issues if i["severity"] == "error"]
    assert any("agent_id" in e["message"] for e in errors)


def test_unknown_field_warning(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "t", "agent_id": "a1", "extra_field": "x"},
    ])
    issues = validate_evidence_schema(evidence)
    warnings = [i for i in issues if i["severity"] == "warning"]
    assert any("extra_field" in w["message"] for w in warnings)


def test_strict_mode_unknown_field_error(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "t", "agent_id": "a1", "extra": "x"},
    ])
    issues = validate_evidence_schema(evidence, strict=True)
    errors = [i for i in issues if i["severity"] == "error"]
    assert any("extra" in e["message"] for e in errors)


def test_missing_file_warning(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "t", "agent_id": "a1"},
    ])
    issues = validate_evidence_schema(evidence)
    warnings = [i for i in issues if i["severity"] == "warning"]
    assert any("transcripts.jsonl" in w["message"] for w in warnings)


def test_not_a_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        validate_evidence_schema(tmp_path / "nonexistent")


def test_format_schema_text() -> None:
    text = format_schema_text()
    assert "Evidence File Schemas" in text
    assert "messages.jsonl" in text
    assert "transcripts.jsonl" in text
    assert "control_plane.jsonl" in text
    assert "required" in text
    assert "optional" in text


def test_format_validation_no_issues() -> None:
    text = format_validation_text([])
    assert "no issues" in text.lower()


def test_format_validation_with_issues() -> None:
    issues = [
        {"file": "messages.jsonl", "line": 1, "severity": "error", "message": "Missing field: agent_id"},
        {"file": "messages.jsonl", "line": 2, "severity": "warning", "message": "Unknown field: extra"},
    ]
    text = format_validation_text(issues)
    assert "ERROR" in text
    assert "WARN" in text
    assert "1 error" in text
    assert "1 warning" in text


def test_invalid_json_line(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "messages.jsonl").write_text("not json\n", encoding="utf-8")
    issues = validate_evidence_schema(evidence)
    errors = [i for i in issues if i["severity"] == "error"]
    assert any("Invalid JSON" in e["message"] for e in errors)


def test_cli_evidence_schema_print(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    args = cli.build_parser().parse_args(["evidence-schema", "--print"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "messages.jsonl" in output
    assert "transcripts.jsonl" in output


def test_cli_evidence_schema_validate(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "t", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "t1", "actual_tool": "t1"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [
        {"event_id": "cp1", "agent_id": "a1", "tool": "t1"},
    ])

    args = cli.build_parser().parse_args([
        "evidence-schema", "--validate", str(evidence), "--format", "json",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    errors = [i for i in data if i["severity"] == "error"]
    assert len(errors) == 0
