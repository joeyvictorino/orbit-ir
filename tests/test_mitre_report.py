"""Tests for mitre_report module."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.mitre_report import (
    MitreReportGenerator,
    TECHNIQUE_CATALOG,
    ALL_TACTICS,
    generate_mitre_report,
    format_mitre_report_text,
    _technique_for_event,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {"agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z", "detection_type": "tool-name-mismatch", "type": "alert"},
        {"agent_id": "a2", "timestamp": "2026-01-01T00:01:00Z", "detection_type": "lateral-resource-access", "type": "alert"},
        {"agent_id": "a1", "timestamp": "2026-01-01T00:02:00Z", "mitre_technique": "T1078", "type": "login"},
        {"agent_id": "a3", "timestamp": "2026-01-01T00:03:00Z", "tags": ["MITRE:T1059"], "type": "exec"},
        {"agent_id": "a1", "timestamp": "2026-01-01T00:04:00Z", "detection_type": "missing-transcript", "type": "alert"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp_path


def test_technique_catalog_has_min_entries():
    assert len(TECHNIQUE_CATALOG) >= 20


def test_all_tactics_covered():
    tactics_in_catalog = {info["tactic"] for info in TECHNIQUE_CATALOG.values()}
    for tactic in ALL_TACTICS:
        assert tactic in tactics_in_catalog, f"Missing tactic: {tactic}"


def test_technique_for_event_detection_type():
    ev = {"detection_type": "tool-name-mismatch"}
    tids = _technique_for_event(ev)
    assert "T1036" in tids


def test_technique_for_event_mitre_tag():
    ev = {"tags": ["MITRE:T1059"]}
    tids = _technique_for_event(ev)
    assert "T1059" in tids


def test_technique_for_event_mitre_field():
    ev = {"mitre_technique": "T1078"}
    tids = _technique_for_event(ev)
    assert "T1078" in tids


def test_technique_for_event_no_match():
    ev = {"type": "boring_event"}
    tids = _technique_for_event(ev)
    assert tids == []


def test_load_and_build(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    data = gen.to_dict()
    assert data["total_events"] == 5
    assert data["total_techniques"] == len(TECHNIQUE_CATALOG)
    assert data["observed_techniques"] >= 3


def test_coverage_pct(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    data = gen.to_dict()
    assert 0 < data["coverage_pct"] <= 100


def test_tactic_breakdown(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    data = gen.to_dict()
    tactics = {t["tactic"] for t in data["tactics"]}
    assert "Defense Evasion" in tactics
    assert "Lateral Movement" in tactics


def test_example_events(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    data = gen.to_dict()
    for ts in data["tactics"]:
        for tech in ts["techniques"]:
            if tech["observed"]:
                assert "example_events" in tech
                assert len(tech["example_events"]) >= 1


def test_format_text(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    text = format_mitre_report_text(gen.to_dict())
    assert "MITRE ATT&CK Coverage Report" in text
    assert "T1036" in text


def test_empty_evidence(tmp_path: Path):
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    gen = generate_mitre_report(tmp_path)
    data = gen.to_dict()
    assert data["total_events"] == 0
    assert data["observed_techniques"] == 0
    assert data["coverage_pct"] == 0.0


def test_json_output_structure(evidence_dir: Path):
    gen = generate_mitre_report(evidence_dir)
    data = gen.to_dict()
    assert "tactics" in data
    assert isinstance(data["tactics"], list)
    for ts in data["tactics"]:
        assert "tactic" in ts
        assert "techniques" in ts
        assert "coverage_pct" in ts


def test_dedup_technique_ids():
    ev = {"detection_type": "tool-name-mismatch", "mitre_technique": "T1036"}
    tids = _technique_for_event(ev)
    assert tids.count("T1036") == 1


def test_reasons_mapping():
    ev = {"reasons": [{"detection_type": "oracle-integrity-violation"}]}
    tids = _technique_for_event(ev)
    assert "T1565" in tids
