"""Tests for orbit_ir.convert."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from orbit_ir.convert import (
    convert_csv_to_jsonl,
    convert_evidence_dir,
    convert_jsonl_to_csv,
    format_convert_text,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_jsonl_to_csv_basic(tmp_path: Path) -> None:
    src = tmp_path / "msgs.jsonl"
    _write_jsonl(src, [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
        {"event_id": "m2", "agent_id": "a2", "timestamp": "2026-01-01T00:01:00Z"},
    ])
    dst = tmp_path / "msgs.csv"
    result = convert_jsonl_to_csv(src, dst)
    assert result["rows"] == 2
    assert result["columns"] == 3
    assert dst.exists()

    with dst.open("r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["event_id"] == "m1"


def test_csv_to_jsonl_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "msgs.jsonl"
    _write_jsonl(src, [
        {"event_id": "m1", "agent_id": "a1", "count": 5},
    ])
    csv_path = tmp_path / "msgs.csv"
    convert_jsonl_to_csv(src, csv_path)

    out = tmp_path / "roundtrip.jsonl"
    result = convert_csv_to_jsonl(csv_path, out)
    assert result["rows"] == 1

    with out.open("r") as f:
        row = json.loads(f.readline())
    assert row["event_id"] == "m1"
    assert row["agent_id"] == "a1"
    assert row["count"] == 5


def test_nested_field_flattening(tmp_path: Path) -> None:
    src = tmp_path / "data.jsonl"
    _write_jsonl(src, [
        {"id": "1", "tool": {"name": "http_get", "version": "1.0"}},
    ])
    dst = tmp_path / "data.csv"
    result = convert_jsonl_to_csv(src, dst)
    assert result["columns"] == 3

    with dst.open("r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert rows[0]["tool.name"] == "http_get"
    assert rows[0]["tool.version"] == "1.0"


def test_directory_conversion(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "t1", "actual_tool": "t1"},
    ])

    out = tmp_path / "csv_out"
    result = convert_evidence_dir(evidence, out, "csv")
    assert result["files_converted"] == 2
    assert result["total_rows"] == 2
    assert (out / "messages.csv").exists()
    assert (out / "transcripts.csv").exists()


def test_empty_file(tmp_path: Path) -> None:
    src = tmp_path / "empty.jsonl"
    src.write_text("", encoding="utf-8")
    dst = tmp_path / "empty.csv"
    result = convert_jsonl_to_csv(src, dst)
    assert result["rows"] == 0


def test_format_convert_text() -> None:
    result = {
        "files_converted": 2,
        "total_rows": 10,
        "target_format": "csv",
        "details": [
            {"input": "a.jsonl", "output": "a.csv", "rows": 5},
            {"input": "b.jsonl", "output": "b.csv", "rows": 5},
        ],
    }
    text = format_convert_text(result)
    assert "2 file(s)" in text
    assert "10" in text


def test_none_value_handling(tmp_path: Path) -> None:
    src = tmp_path / "data.jsonl"
    _write_jsonl(src, [
        {"id": "1", "value": None},
    ])
    csv_path = tmp_path / "data.csv"
    convert_jsonl_to_csv(src, csv_path)

    out = tmp_path / "back.jsonl"
    convert_csv_to_jsonl(csv_path, out)
    with out.open("r") as f:
        row = json.loads(f.readline())
    assert row["value"] is None


def test_cli_convert_jsonl_to_csv(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "msgs.jsonl"
    _write_jsonl(evidence, [{"event_id": "m1", "agent_id": "a1", "timestamp": "t"}])
    out = tmp_path / "msgs.csv"

    args = cli.build_parser().parse_args([
        "convert", "--input", str(evidence), "--output", str(out), "--to", "csv",
    ])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    assert out.exists()
    assert "1 rows" in buf.getvalue() or "Rows: 1" in buf.getvalue()
