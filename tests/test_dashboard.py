"""Tests for orbit_ir.dashboard."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.dashboard import generate_dashboard


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _setup_evidence(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:07Z", "agent_id": "a2", "recipient_agent_id": None},
            {"event_id": "m3", "timestamp": "2026-07-08T18:00:10Z", "agent_id": "a1", "recipient_agent_id": "a3"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
            {"call_id": "c2", "agent_id": "a2", "claimed_tool": "shell_exec", "actual_tool": "shell_exec"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "http_get"}],
    )
    return evidence


def test_dashboard_generates_html(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "report.html"
    result = generate_dashboard(evidence, output)

    assert output.exists()
    html_content = output.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert result["agents"] == 3
    assert result["messages"] == 3
    assert result["transcripts"] == 2
    assert result["generated_at"]


def test_dashboard_contains_sections(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "dash.html"
    generate_dashboard(evidence, output, title="Test Dashboard")

    html_content = output.read_text(encoding="utf-8")
    assert "Test Dashboard" in html_content
    assert "Severity Breakdown" in html_content
    assert "Agent Activity" in html_content
    assert "Agents" in html_content
    assert "Messages" in html_content


def test_dashboard_contains_agent_data(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "dash.html"
    generate_dashboard(evidence, output)

    html_content = output.read_text(encoding="utf-8")
    assert "a1" in html_content
    assert "a2" in html_content
    assert "http_get" in html_content


def test_dashboard_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "empty.html"
    result = generate_dashboard(evidence, output)

    assert output.exists()
    assert result["agents"] == 0
    assert result["messages"] == 0
    html_content = output.read_text(encoding="utf-8")
    assert "No findings" in html_content or "Findings (0)" in html_content


def test_dashboard_not_a_directory(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        generate_dashboard(tmp_path / "nonexistent", tmp_path / "out.html")


def test_dashboard_dark_mode_support(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "dash.html"
    generate_dashboard(evidence, output)

    html_content = output.read_text(encoding="utf-8")
    assert "prefers-color-scheme: dark" in html_content


def test_dashboard_creates_parent_dirs(tmp_path: Path) -> None:
    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "deep" / "nested" / "dash.html"
    result = generate_dashboard(evidence, output)
    assert output.exists()


def test_dashboard_cli_json(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from orbit_ir import cli

    evidence = _setup_evidence(tmp_path)
    output = tmp_path / "cli_dash.html"

    args = cli.build_parser().parse_args(["dashboard", "--input", str(evidence), "--output", str(output)])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    data = json.loads(buf.getvalue())
    assert data["agents"] == 3
    assert output.exists()
