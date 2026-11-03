from __future__ import annotations

import json
import pytest
from pathlib import Path

from orbit_ir.evidence_score import (
    score_evidence,
    format_evidence_score_text,
    _quality_level,
    _volume_score,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    d = tmp_path / "evidence"
    d.mkdir()

    agents = [
        {"agent_id": "a1", "name": "Agent Alpha"},
        {"agent_id": "a2", "name": "Agent Beta"},
    ]
    (d / "agents.jsonl").write_text(
        "\n".join(json.dumps(a) for a in agents)
    )

    messages = [
        {"message_id": "m1", "agent_id": "a1", "content": "hello"},
        {"message_id": "m2", "agent_id": "a2", "content": "world"},
        {"message_id": "m3", "agent_id": "a1", "content": "test"},
    ]
    (d / "messages.jsonl").write_text(
        "\n".join(json.dumps(m) for m in messages)
    )
    return d


@pytest.fixture
def incomplete_dir(tmp_path: Path) -> Path:
    d = tmp_path / "incomplete"
    d.mkdir()
    agents = [
        {"agent_id": "a1"},
        {"agent_id": "a2", "name": "Beta"},
    ]
    (d / "agents.jsonl").write_text(
        "\n".join(json.dumps(a) for a in agents)
    )
    return d


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    d = tmp_path / "empty"
    d.mkdir()
    return d


def test_empty_dir(empty_dir: Path) -> None:
    result = score_evidence(empty_dir)
    assert result.quality_level == "none"
    assert result.total_files == 0


def test_evidence_dir(evidence_dir: Path) -> None:
    result = score_evidence(evidence_dir)
    assert result.total_files == 2
    assert result.total_records == 5
    assert result.overall_score > 0
    assert result.quality_level != "none"
    assert len(result.dimensions) == 4


def test_incomplete_fields(incomplete_dir: Path) -> None:
    result = score_evidence(incomplete_dir)
    assert result.total_files == 1
    agent_file = result.file_scores[0]
    assert agent_file.completeness < 100.0
    assert "missing required field" in " ".join(agent_file.issues)


def test_single_file(evidence_dir: Path) -> None:
    result = score_evidence(evidence_dir / "agents.jsonl")
    assert result.total_files == 1
    assert result.total_records == 2


def test_coverage_dimension(evidence_dir: Path) -> None:
    result = score_evidence(evidence_dir)
    coverage = next(d for d in result.dimensions if d.name == "coverage")
    assert coverage.score == 50.0


def test_quality_level() -> None:
    assert _quality_level(90) == "excellent"
    assert _quality_level(70) == "good"
    assert _quality_level(50) == "adequate"
    assert _quality_level(30) == "poor"
    assert _quality_level(10) == "insufficient"


def test_volume_score() -> None:
    assert _volume_score(0) == 0.0
    assert _volume_score(5) == 20.0
    assert _volume_score(50) == 40.0
    assert _volume_score(500) == 60.0
    assert _volume_score(5000) == 80.0
    assert _volume_score(50000) == 100.0


def test_format_text(evidence_dir: Path) -> None:
    result = score_evidence(evidence_dir)
    text = format_evidence_score_text(result.to_dict())
    assert "Evidence Quality Score" in text
    assert "Overall Score:" in text
    assert "Quality Dimensions:" in text
    assert "File Details:" in text


def test_json_input(tmp_path: Path) -> None:
    data = {"findings": [
        {"agent_id": "a1", "type": "test", "severity": "high"},
        {"agent_id": "a2", "type": "test2", "severity": "low"},
    ]}
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(data))
    result = score_evidence(p)
    assert result.total_records == 2
    assert result.total_files == 1
