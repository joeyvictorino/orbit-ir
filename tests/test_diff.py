"""Tests for the diff command."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from orbit_ir.diff import diff_results, format_diff_text, load_results


FIELDNAMES = (
    "finding_id", "tool_call_id", "agent_id_transcript", "agent_id_control",
    "trace_id_transcript", "trace_id_control", "reasons",
    "transcript_source", "transcript_line", "control_source", "control_line",
    "claimed_tool", "actual_tool", "effect", "confidence",
)


def _write_results(d: Path, summary: dict, findings: list[dict]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with (d / "findings.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in findings:
            writer.writerow({k: row.get(k, "") for k in FIELDNAMES})


def _make_summary(agents: int = 100, findings_count: int = 5) -> dict:
    return {
        "corpus": {"agents": agents, "messages": 1000},
        "findings": {"record_conflicts": findings_count, "transcript_tool_call_mismatches": findings_count},
    }


def _make_finding(fid: str, tc_id: str, confidence: str = "high", reasons: str = "tool-name-mismatch") -> dict:
    return {
        "finding_id": fid,
        "tool_call_id": tc_id,
        "agent_id_transcript": "agent-001",
        "agent_id_control": "agent-001",
        "trace_id_transcript": "tr-1",
        "trace_id_control": "tr-1",
        "reasons": reasons,
        "transcript_source": "transcripts.jsonl",
        "transcript_line": "10",
        "control_source": "control_plane.jsonl",
        "control_line": "10",
        "claimed_tool": "read_file",
        "actual_tool": "exec_command",
        "effect": "file_write",
        "confidence": confidence,
    }


def test_identical_results(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    findings = [_make_finding("f-1", "tc-1")]
    _write_results(before, _make_summary(), findings)
    _write_results(after, _make_summary(), findings)

    result = diff_results(before, after)
    assert result["new_findings"] == []
    assert result["resolved_findings"] == []
    assert result["changed_findings"] == []
    assert result["corpus_delta"] == {}
    assert result["findings_summary_delta"] == {}


def test_new_finding(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(), [_make_finding("f-1", "tc-1")])
    _write_results(after, _make_summary(), [_make_finding("f-1", "tc-1"), _make_finding("f-2", "tc-2")])

    result = diff_results(before, after)
    assert len(result["new_findings"]) == 1
    assert result["new_findings"][0]["finding_id"] == "f-2"
    assert result["resolved_findings"] == []


def test_resolved_finding(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(), [_make_finding("f-1", "tc-1"), _make_finding("f-2", "tc-2")])
    _write_results(after, _make_summary(), [_make_finding("f-1", "tc-1")])

    result = diff_results(before, after)
    assert result["new_findings"] == []
    assert len(result["resolved_findings"]) == 1
    assert result["resolved_findings"][0]["finding_id"] == "f-2"


def test_changed_confidence(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(), [_make_finding("f-1", "tc-1", confidence="low")])
    _write_results(after, _make_summary(), [_make_finding("f-1", "tc-1", confidence="high")])

    result = diff_results(before, after)
    assert result["new_findings"] == []
    assert result["resolved_findings"] == []
    assert len(result["changed_findings"]) == 1
    assert result["changed_findings"][0]["changes"]["confidence"] == {"before": "low", "after": "high"}


def test_corpus_delta(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(agents=100), [])
    _write_results(after, _make_summary(agents=200), [])

    result = diff_results(before, after)
    assert "agents" in result["corpus_delta"]
    assert result["corpus_delta"]["agents"]["delta"] == 100


def test_empty_results(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(), [])
    _write_results(after, _make_summary(), [])

    result = diff_results(before, after)
    assert result["before_total_findings"] == 0
    assert result["after_total_findings"] == 0


def test_format_text_no_diff(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(), [_make_finding("f-1", "tc-1")])
    _write_results(after, _make_summary(), [_make_finding("f-1", "tc-1")])

    result = diff_results(before, after)
    text = format_diff_text(result)
    assert "No differences found." in text


def test_format_text_with_changes(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_results(before, _make_summary(agents=100), [_make_finding("f-1", "tc-1")])
    _write_results(after, _make_summary(agents=200), [_make_finding("f-1", "tc-1"), _make_finding("f-2", "tc-2")])

    result = diff_results(before, after)
    text = format_diff_text(result)
    assert "NEW findings (1):" in text
    assert "f-2" in text
    assert "Corpus changes:" in text


def test_load_missing_summary(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        load_results(tmp_path)


def test_load_no_csv(tmp_path: Path) -> None:
    (tmp_path / "summary.json").write_text(json.dumps({"corpus": {}, "findings": {}}))
    summary, findings = load_results(tmp_path)
    assert findings == []
    assert "corpus" in summary
