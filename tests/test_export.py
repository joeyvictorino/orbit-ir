"""Tests for orbit_ir.export."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from orbit_ir.export import export_findings, findings_to_csv


_SAMPLE_FINDINGS = [
    {
        "finding_id": "f1",
        "tool_call_id": "tc1",
        "agent_id_transcript": "agent-001",
        "agent_id_control": "agent-001",
        "trace_id_transcript": "tr-1",
        "trace_id_control": "tr-1",
        "reasons": ["tool-name-mismatch"],
        "mitre_techniques": [{"id": "T1036", "name": "Masquerading"}],
        "transcript_source": "transcripts.jsonl",
        "transcript_line": 5,
        "control_source": "control_plane.jsonl",
        "control_line": 3,
        "claimed_tool": "http_get",
        "actual_tool": "shell_exec",
        "effect": "code_execution",
        "confidence": "high",
        "confidence_score": 0.95,
        "severity": "high",
    },
    {
        "finding_id": "f2",
        "tool_call_id": "tc2",
        "agent_id_transcript": "agent-002",
        "agent_id_control": "agent-003",
        "trace_id_transcript": "tr-2",
        "trace_id_control": "tr-2",
        "reasons": ["agent-id-mismatch", "trace-id-mismatch"],
        "mitre_techniques": [],
        "transcript_source": "transcripts.jsonl",
        "transcript_line": 10,
        "control_source": "control_plane.jsonl",
        "control_line": 7,
        "claimed_tool": "http_post",
        "actual_tool": "http_post",
        "effect": None,
        "confidence": "medium",
        "confidence_score": 0.6,
        "severity": "medium",
    },
]


def _write_findings(path: Path, findings: list[dict]) -> Path:
    findings_path = path / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return findings_path


def test_export_csv(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    text = export_findings(fp, "csv")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["finding_id"] == "f1"
    assert rows[0]["reasons"] == "tool-name-mismatch"
    assert rows[0]["mitre_techniques"] == "T1036:Masquerading"
    assert rows[1]["reasons"] == "agent-id-mismatch;trace-id-mismatch"


def test_export_cef(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    text = export_findings(fp, "cef")
    lines = text.strip().split("\n")
    assert len(lines) == 2
    assert lines[0].startswith("CEF:0|ORBIT|AgentIR|1.0|tool-name-mismatch|")
    assert "src=agent-001" in lines[0]


def test_export_sarif(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    text = export_findings(fp, "sarif")
    sarif = json.loads(text)
    assert sarif["$schema"] == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert len(runs) == 1
    assert len(runs[0]["results"]) >= 2


def test_export_json(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    text = export_findings(fp, "json")
    data = json.loads(text)
    assert len(data) == 2
    assert data[0]["finding_id"] == "f1"


def test_export_to_file(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    out = tmp_path / "exported.csv"
    text = export_findings(fp, "csv", output_path=out)
    assert out.exists()
    assert out.read_text(encoding="utf-8").replace("\r\n", "\n") == text.replace("\r\n", "\n")


def test_export_unsupported_format(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    with pytest.raises(ValueError, match="unsupported export format"):
        export_findings(fp, "xml")


def test_export_empty_findings(tmp_path: Path) -> None:
    fp = _write_findings(tmp_path, [])
    csv_text = export_findings(fp, "csv")
    reader = csv.DictReader(io.StringIO(csv_text))
    assert list(reader) == []

    cef_text = export_findings(fp, "cef")
    assert cef_text == ""


def test_findings_to_csv_preserves_field_order() -> None:
    text = findings_to_csv(_SAMPLE_FINDINGS)
    header = text.split("\n")[0].strip("\r")
    fields = header.split(",")
    assert fields[0] == "finding_id"
    assert fields[1] == "tool_call_id"
    assert any("confidence_score" in f for f in fields)


def test_export_cli_csv(tmp_path: Path) -> None:
    from orbit_ir import cli
    import io as stdio
    from contextlib import redirect_stdout

    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    args = cli.build_parser().parse_args(["export", "--input", str(fp), "--format", "csv"])
    buf = stdio.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "finding_id" in output
    assert "tool-name-mismatch" in output


def test_export_cli_cef(tmp_path: Path) -> None:
    from orbit_ir import cli
    import io as stdio
    from contextlib import redirect_stdout

    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    args = cli.build_parser().parse_args(["export", "--input", str(fp), "--format", "cef"])
    buf = stdio.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "CEF:0" in output


def test_export_cli_to_file(tmp_path: Path) -> None:
    from orbit_ir import cli

    fp = _write_findings(tmp_path, _SAMPLE_FINDINGS)
    out = tmp_path / "out.sarif"
    args = cli.build_parser().parse_args(["export", "--input", str(fp), "--format", "sarif", "--out", str(out)])
    cli._run(args)
    assert out.exists()
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
