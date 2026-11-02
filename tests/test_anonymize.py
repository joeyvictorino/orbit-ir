"""Tests for orbit_ir.anonymize."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.anonymize import anonymize_evidence, format_anonymize_text, Anonymizer


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path) -> None:
    evidence.mkdir(exist_ok=True)
    _write_jsonl(
        evidence / "messages.jsonl",
        [
            {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z",
             "agent_id": "alice", "recipient_agent_id": "bob"},
            {"event_id": "m2", "timestamp": "2026-07-08T18:00:05Z",
             "agent_id": "bob", "recipient_agent_id": "alice"},
        ],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [
            {"call_id": "c1", "agent_id": "alice",
             "claimed_tool": "curl", "actual_tool": "curl"},
            {"call_id": "c2", "agent_id": "alice",
             "claimed_tool": "curl", "actual_tool": "shell_exec"},
        ],
    )


def test_anonymize_replaces_ids(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "anon"
    result = anonymize_evidence(evidence, out)
    assert result["files_processed"] == 2
    assert result["identifiers_replaced"] > 0

    rows = []
    for f in sorted(out.glob("*.jsonl")):
        with f.open() as fp:
            for line in fp:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))

    agent_ids = {r.get("agent_id") for r in rows if "agent_id" in r}
    assert "alice" not in agent_ids
    assert "bob" not in agent_ids
    for aid in agent_ids:
        assert aid.startswith("agent_")


def test_anonymize_preserves_correlations(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "anon"
    anonymize_evidence(evidence, out)

    msgs = []
    with (out / "messages.jsonl").open() as f:
        for line in f:
            if line.strip():
                msgs.append(json.loads(line))

    assert msgs[0]["agent_id"] == msgs[1]["recipient_agent_id"]
    assert msgs[1]["agent_id"] == msgs[0]["recipient_agent_id"]


def test_anonymize_deterministic(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out1 = tmp_path / "a1"
    out2 = tmp_path / "a2"
    anonymize_evidence(evidence, out1, salt="test")
    anonymize_evidence(evidence, out2, salt="test")

    for fname in ("messages.jsonl", "transcripts.jsonl"):
        t1 = (out1 / fname).read_text()
        t2 = (out2 / fname).read_text()
        assert t1 == t2


def test_anonymize_save_mapping(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "anon"
    result = anonymize_evidence(evidence, out, save_mapping=True)
    assert result["mapping_saved"] is True
    mapping_path = out / "anonymization_mapping.json"
    assert mapping_path.exists()
    mapping = json.loads(mapping_path.read_text())
    assert "agent" in mapping
    assert "alice" in mapping["agent"]


def test_anonymize_not_a_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        anonymize_evidence(tmp_path / "nope", tmp_path / "out")


def test_anonymizer_pseudonym_consistency() -> None:
    anon = Anonymizer(salt="x")
    p1 = anon.pseudonym("alice", "agent")
    p2 = anon.pseudonym("alice", "agent")
    assert p1 == p2
    p3 = anon.pseudonym("bob", "agent")
    assert p3 != p1


def test_anonymizer_empty_value() -> None:
    anon = Anonymizer()
    assert anon.pseudonym("", "agent") == ""
    assert anon.pseudonym(None, "agent") is None


def test_format_anonymize_text(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "anon"
    result = anonymize_evidence(evidence, out)
    text = format_anonymize_text(result)
    assert "Anonymized" in text
    assert "Identifiers replaced" in text
