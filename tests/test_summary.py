"""Tests for orbit_ir.summary."""

from __future__ import annotations

import json
from pathlib import Path

from orbit_ir.summary import build_executive_summary, format_summary_text


def _make_results(tmp_path: Path, summary: dict, findings: list[dict]) -> Path:
    results = tmp_path / "results"
    results.mkdir()
    (results / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (results / "findings.json").write_text(
        json.dumps(findings, indent=2), encoding="utf-8"
    )
    return results


def _sample_summary() -> dict:
    return {
        "synthetic": True,
        "scenario": "Test exercise",
        "corpus": {
            "agents": 10,
            "messages": 5000,
            "first_timestamp": "2026-07-08T18:00:00Z",
            "last_timestamp": "2026-07-08T19:00:00Z",
        },
        "findings": {
            "risk_score": 72.5,
            "risk_rating": "high",
            "confidence_bands": {"high": 5, "medium": 3, "low": 2},
            "average_confidence_score": 0.75,
            "coordinators_over_threshold": 2,
            "lateral_movement_detections": 1,
            "shared_credentials": 3,
            "agent_clusters": 2,
            "oracle_integrity_violations": 1,
        },
    }


def _sample_findings() -> list[dict]:
    return [
        {
            "detection_type": "tool-name-mismatch",
            "severity": "critical",
            "agent_id": "agent-007",
            "mitre_techniques": [{"technique_id": "T1059"}],
        },
        {
            "detection_type": "tool-name-mismatch",
            "severity": "high",
            "agent_id": "agent-007",
            "mitre_techniques": [{"technique_id": "T1059"}],
        },
        {
            "detection_type": "unbacked-completion",
            "severity": "medium",
            "agent_id": "agent-042",
            "mitre_techniques": [],
        },
        {
            "detection_type": "missing-transcript",
            "severity": "low",
            "agent_id": "agent-099",
            "mitre_techniques": [],
        },
    ]


def test_build_executive_summary(tmp_path: Path) -> None:
    results = _make_results(tmp_path, _sample_summary(), _sample_findings())
    es = build_executive_summary(results)

    assert es["overview"]["total_findings"] == 4
    assert es["overview"]["risk_score"] == 72.5
    assert es["overview"]["risk_rating"] == "high"
    assert es["overview"]["corpus_agents"] == 10

    assert es["severity_breakdown"]["critical"] == 1
    assert es["severity_breakdown"]["high"] == 1
    assert es["severity_breakdown"]["medium"] == 1
    assert es["severity_breakdown"]["low"] == 1

    assert len(es["top_detection_types"]) == 3
    assert es["top_detection_types"][0]["type"] == "tool-name-mismatch"
    assert es["top_detection_types"][0]["count"] == 2

    assert es["affected_agents"]["count"] == 3

    assert len(es["top_mitre_techniques"]) == 1
    assert es["top_mitre_techniques"][0]["technique"] == "T1059"

    assert es["key_indicators"]["coordinators_detected"] == 2
    assert es["key_indicators"]["lateral_movement"] == 1

    assert len(es["recommendations"]) >= 3


def test_recommendations_critical_findings(tmp_path: Path) -> None:
    results = _make_results(tmp_path, _sample_summary(), _sample_findings())
    es = build_executive_summary(results)
    priorities = [r["priority"] for r in es["recommendations"]]
    assert "critical" in priorities


def test_recommendations_clean(tmp_path: Path) -> None:
    summary = _sample_summary()
    summary["findings"]["risk_score"] = 0
    summary["findings"]["risk_rating"] = "low"
    summary["findings"]["coordinators_over_threshold"] = 0
    summary["findings"]["lateral_movement_detections"] = 0
    summary["findings"]["shared_credentials"] = 0
    summary["findings"]["oracle_integrity_violations"] = 0
    results = _make_results(tmp_path, summary, [])
    es = build_executive_summary(results)
    assert es["recommendations"][0]["priority"] == "info"


def test_format_text(tmp_path: Path) -> None:
    results = _make_results(tmp_path, _sample_summary(), _sample_findings())
    es = build_executive_summary(results)
    text = format_summary_text(es)
    assert "EXECUTIVE SUMMARY" in text
    assert "HIGH" in text
    assert "critical" in text.lower()
    assert "Recommendations:" in text


def test_missing_summary_file(tmp_path: Path) -> None:
    results = tmp_path / "empty"
    results.mkdir()
    try:
        build_executive_summary(results)
        assert False, "should have raised"
    except FileNotFoundError:
        pass


def test_no_findings_file(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    (results / "summary.json").write_text(
        json.dumps(_sample_summary()), encoding="utf-8"
    )
    es = build_executive_summary(results)
    assert es["overview"]["total_findings"] == 0
    assert all(v == 0 for v in es["severity_breakdown"].values())


def test_mitre_string_format(tmp_path: Path) -> None:
    findings = [
        {
            "detection_type": "test",
            "severity": "medium",
            "agent_id": "a1",
            "mitre_techniques": ["T1059", "T1071"],
        }
    ]
    results = _make_results(tmp_path, _sample_summary(), findings)
    es = build_executive_summary(results)
    assert len(es["top_mitre_techniques"]) == 2
