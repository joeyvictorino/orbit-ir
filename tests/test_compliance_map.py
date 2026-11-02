from __future__ import annotations

import json
import pytest
from pathlib import Path

from orbit_ir.compliance_map import (
    map_compliance,
    format_compliance_map_text,
    _normalize_type,
    FRAMEWORK_CONTROLS,
)


@pytest.fixture
def findings_file(tmp_path: Path) -> Path:
    data = {
        "findings": [
            {"detection_type": "credential_reuse", "severity": "high", "agent_id": "a1"},
            {"detection_type": "lateral_movement", "severity": "critical", "agent_id": "a2"},
            {"detection_type": "spoofed_tool_call", "severity": "high", "agent_id": "a1"},
            {"detection_type": "data_exfiltration", "severity": "critical", "agent_id": "a3"},
        ]
    }
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"findings": []}))
    return p


def test_empty_findings(empty_file: Path) -> None:
    result = map_compliance(empty_file)
    assert result.total_findings == 0
    assert result.frameworks == []


def test_all_frameworks(findings_file: Path) -> None:
    result = map_compliance(findings_file)
    assert result.total_findings == 4
    assert len(result.frameworks) == 3
    fw_names = {fw.framework for fw in result.frameworks}
    assert "NIST_800-53" in fw_names
    assert "SOC2_TSC" in fw_names
    assert "ISO_27001" in fw_names


def test_single_framework(findings_file: Path) -> None:
    result = map_compliance(findings_file, frameworks=["NIST_800-53"])
    assert len(result.frameworks) == 1
    fw = result.frameworks[0]
    assert fw.framework == "NIST_800-53"
    assert fw.triggered_controls > 0
    assert fw.coverage_pct > 0


def test_triggered_controls(findings_file: Path) -> None:
    result = map_compliance(findings_file, frameworks=["NIST_800-53"])
    fw = result.frameworks[0]
    triggered = [c for c in fw.controls if c.finding_count > 0]
    assert len(triggered) > 0
    ctrl_ids = {c.control_id for c in triggered}
    assert "IA-5" in ctrl_ids or "IA-6" in ctrl_ids


def test_normalize_type() -> None:
    assert _normalize_type("claim_vs_check") == "spoofed_tool_call"
    assert _normalize_type("oracle_integrity") == "data_tampering"
    assert _normalize_type("lateral") == "lateral_movement"
    assert _normalize_type("unknown_type") == "unknown_type"


def test_unmapped_types(tmp_path: Path) -> None:
    data = {"findings": [{"detection_type": "totally_novel", "severity": "low"}]}
    p = tmp_path / "novel.json"
    p.write_text(json.dumps(data))
    result = map_compliance(p)
    assert "totally_novel" in result.unmapped_types


def test_format_text(findings_file: Path) -> None:
    result = map_compliance(findings_file)
    text = format_compliance_map_text(result.to_dict())
    assert "Compliance Framework Mapping" in text
    assert "NIST_800-53" in text
    assert "SOC2_TSC" in text
    assert "Controls triggered:" in text


def test_list_input(tmp_path: Path) -> None:
    data = [
        {"detection_type": "credential_reuse", "severity": "high"},
        {"detection_type": "command_injection", "severity": "medium"},
    ]
    p = tmp_path / "list.json"
    p.write_text(json.dumps(data))
    result = map_compliance(p, frameworks=["NIST_800-53"])
    assert result.total_findings == 2
    assert result.frameworks[0].triggered_controls > 0
