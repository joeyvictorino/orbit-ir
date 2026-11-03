"""Tests for orbit_ir.enrich."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.enrich import enrich_evidence, format_enrich_text


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


def test_enrich_tool_docs(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    _write_jsonl(evidence / "messages.jsonl", [])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
        {"call_id": "c2", "agent_id": "a2", "claimed_tool": "unknown_tool", "actual_tool": "unknown_tool"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [
        {"event_id": "cp1", "agent_id": "a1", "tool": "shell_exec"},
    ])

    result = enrich_evidence(evidence, output, enrichments=["tool_docs"])
    assert result["summary"]["tool_docs_applied"] == 2  # http_get + shell_exec

    transcripts = _read_jsonl(output / "transcripts.jsonl")
    assert transcripts[0].get("tool_description") is not None
    assert transcripts[1].get("tool_description") is None  # unknown_tool

    control = _read_jsonl(output / "control_plane.jsonl")
    assert control[0].get("tool_description") is not None


def test_enrich_agent_roles(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    # a1 sends to 3+ distinct agents -> orchestrator
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
        {"event_id": "m2", "timestamp": "2026-01-01T00:00:01Z", "agent_id": "a1", "recipient_agent_id": "a3"},
        {"event_id": "m3", "timestamp": "2026-01-01T00:00:02Z", "agent_id": "a1", "recipient_agent_id": "a4"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a2", "claimed_tool": "http_get", "actual_tool": "http_get"},
        {"call_id": "c2", "agent_id": "a2", "claimed_tool": "file_read", "actual_tool": "file_read"},
        {"call_id": "c3", "agent_id": "a2", "claimed_tool": "db_query", "actual_tool": "db_query"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    result = enrich_evidence(evidence, output, enrichments=["agent_roles"])
    assert result["summary"]["agent_roles_applied"] > 0

    messages = _read_jsonl(output / "messages.jsonl")
    a1_roles = [m["inferred_role"] for m in messages if m["agent_id"] == "a1"]
    assert all(r == "orchestrator" for r in a1_roles)

    transcripts = _read_jsonl(output / "transcripts.jsonl")
    a2_roles = [t["inferred_role"] for t in transcripts if t["agent_id"] == "a2"]
    assert all(r == "monitor" for r in a2_roles)


def test_enrich_risk_tags(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    _write_jsonl(evidence / "messages.jsonl", [])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "shell_exec", "actual_tool": "shell_exec"},
        {"call_id": "c2", "agent_id": "a1", "claimed_tool": "http_post", "actual_tool": "http_post"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    result = enrich_evidence(evidence, output, enrichments=["risk_tags"])
    assert result["summary"]["risk_tags_applied"] == 2

    transcripts = _read_jsonl(output / "transcripts.jsonl")
    assert "code_execution" in transcripts[0]["risk_tags"]
    assert "network_egress" in transcripts[1]["risk_tags"]


def test_enrich_all_enrichments(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    result = enrich_evidence(evidence, output)
    assert "tool_docs" in result["enrichments"]
    assert "agent_roles" in result["enrichments"]
    assert "risk_tags" in result["enrichments"]
    assert result["files_written"] >= 2


def test_enrich_copies_ground_truth(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])
    (evidence / "ground_truth.json").write_text('{"test": true}', encoding="utf-8")

    enrich_evidence(evidence, output)
    assert (output / "ground_truth.json").exists()
    assert json.loads((output / "ground_truth.json").read_text(encoding="utf-8")) == {"test": True}


def test_enrich_not_a_directory(tmp_path: Path) -> None:
    import pytest
    with pytest.raises(FileNotFoundError):
        enrich_evidence(tmp_path / "nonexistent", tmp_path / "out")


def test_enrich_unknown_enrichment(tmp_path: Path) -> None:
    import pytest
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(ValueError, match="unknown enrichment"):
        enrich_evidence(evidence, tmp_path / "out", enrichments=["bogus"])


def test_format_enrich_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    output = tmp_path / "enriched"

    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [])
    _write_jsonl(evidence / "control_plane.jsonl", [])

    result = enrich_evidence(evidence, output, enrichments=["agent_roles"])
    text = format_enrich_text(result)
    assert "agent_roles" in text
    assert "Files written:" in text
