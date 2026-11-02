from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.risk_score import compute_risk_score, format_risk_score_text


@pytest.fixture
def findings_path(tmp_path: Path) -> Path:
    findings = [
        {"agent_id": "agent-1", "detection_type": "credential_compromise", "severity": "critical"},
        {"agent_id": "agent-2", "detection_type": "tool-name-mismatch", "severity": "high"},
        {"agent_id": "agent-1", "detection_type": "data_exfiltration", "severity": "critical"},
        {"agent_id": "agent-3", "detection_type": "tool-name-mismatch", "severity": "medium"},
    ]
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(findings))
    return p


@pytest.fixture
def empty_path(tmp_path: Path) -> Path:
    p = tmp_path / "empty.json"
    p.write_text("[]")
    return p


def test_compute_risk_score_basic(findings_path: Path) -> None:
    result = compute_risk_score(findings_path)
    d = result.to_dict()
    assert d["total_findings"] == 4
    assert d["agent_count"] == 3
    assert d["composite_score"] > 0
    assert d["risk_level"] in ("low", "medium", "high", "critical")


def test_compute_risk_score_empty(empty_path: Path) -> None:
    result = compute_risk_score(empty_path)
    d = result.to_dict()
    assert d["total_findings"] == 0
    assert d["composite_score"] == 0.0
    assert d["risk_level"] == "low"


def test_risk_score_dimensions(findings_path: Path) -> None:
    result = compute_risk_score(findings_path)
    d = result.to_dict()
    assert len(d["dimensions"]) == 4
    dim_names = {dim["name"] for dim in d["dimensions"]}
    assert dim_names == {"severity", "breadth", "diversity", "density"}


def test_risk_score_severity_weights(findings_path: Path) -> None:
    result = compute_risk_score(findings_path)
    d = result.to_dict()
    assert d["finding_summary"]["critical"] == 2
    assert d["finding_summary"]["high"] == 1
    assert d["finding_summary"]["medium"] == 1


def test_format_risk_score_text(findings_path: Path) -> None:
    result = compute_risk_score(findings_path)
    text = format_risk_score_text(result.to_dict())
    assert "Risk Score" in text
    assert "critical" in text.lower() or "high" in text.lower()


def test_risk_score_custom_weights(findings_path: Path) -> None:
    result = compute_risk_score(findings_path, weights={"severity": 0.5, "breadth": 0.2, "diversity": 0.15, "density": 0.15})
    d = result.to_dict()
    assert d["composite_score"] > 0


def test_risk_score_dict_input(tmp_path: Path) -> None:
    data = {"findings": [
        {"agent_id": "a1", "detection_type": "t1", "severity": "low"},
        {"agent_id": "a1", "detection_type": "t1", "severity": "low"},
    ]}
    p = tmp_path / "dict.json"
    p.write_text(json.dumps(data))
    result = compute_risk_score(p)
    assert result.to_dict()["risk_level"] == "low"


def test_risk_score_high_severity(tmp_path: Path) -> None:
    findings = [
        {"agent_id": f"a{i}", "detection_type": f"t{i}", "severity": "critical"}
        for i in range(20)
    ]
    p = tmp_path / "many.json"
    p.write_text(json.dumps(findings))
    result = compute_risk_score(p)
    d = result.to_dict()
    assert d["risk_level"] in ("high", "critical")
    assert d["composite_score"] >= 50
