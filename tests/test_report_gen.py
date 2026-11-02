"""Tests for orbit_ir.report_gen."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.report_gen import generate_report, ReportConfig


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path) -> None:
    evidence.mkdir(exist_ok=True)
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:05Z", "agent_id": "a2", "recipient_agent_id": None},
            {"event_id": "m3", "timestamp": "2026-07-08T18:00:10Z", "agent_id": "a1", "recipient_agent_id": "a3"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
            {"call_id": "c2", "agent_id": "a1", "claimed_tool": "http_post", "actual_tool": "shell_exec"},
        ],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"event_id": "cp1", "agent_id": "a1", "tool": "http_get"}],
    )


def test_default_all_sections(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    text = generate_report(evidence)
    assert "Summary" in text
    assert "Findings" in text
    assert "Agents" in text
    assert "Timeline" in text
    assert "Tools" in text
    assert "Recommendations" in text


def test_subset_sections(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(sections=["summary", "findings"])
    text = generate_report(evidence, config)
    assert "Summary" in text
    assert "Findings" in text
    assert "\nAgents\n" not in text
    assert "\nTimeline\n" not in text


def test_severity_filter(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(severity_threshold="high", sections=["findings"])
    text = generate_report(evidence, config)
    assert "tool_mismatch" in text
    assert "high_activity" not in text


def test_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    text = generate_report(evidence)
    assert "No findings detected" in text


def test_markdown_format(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(format="markdown", sections=["summary", "findings", "agents"])
    text = generate_report(evidence, config)
    assert "## Summary" in text
    assert "| Agent |" in text
    assert "| Metric |" in text


def test_custom_title(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(title="My Custom Report")
    text = generate_report(evidence, config)
    assert "My Custom Report" in text


def test_not_a_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        generate_report(tmp_path / "nonexistent")


def test_tools_section_shows_mismatches(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(sections=["tools"])
    text = generate_report(evidence, config)
    assert "http_post -> shell_exec" in text


def test_recommendations_for_tool_mismatches(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    config = ReportConfig(sections=["recommendations"])
    text = generate_report(evidence, config)
    assert "tool mismatch" in text.lower()
