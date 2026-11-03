"""Tests for orbit_ir.compliance_check module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.compliance_check import (
    ComplianceChecker,
    check_compliance,
    format_compliance_text,
    list_frameworks,
    _FRAMEWORKS,
)


@pytest.fixture
def compliant_evidence(tmp_path: Path) -> Path:
    events = [
        {"event_type": "account_management", "actual_tool": "create_user", "effect": "user provisioned", "resource": "role_assignment", "timestamp": "2025-01-01T00:01:00Z", "agent_id": "admin-1", "tool_call_id": "tc-1", "source_file": "auth.py"},
        {"event_type": "access_control", "actual_tool": "check_permission", "effect": "role based access granted", "resource": "scoped_access", "policy_decision": "allowed", "credential_id": "cred-1", "timestamp": "2025-01-01T00:02:00Z", "agent_id": "svc-1", "tool_call_id": "tc-2", "source_file": "rbac.py"},
        {"event_type": "audit_log", "type": "monitoring", "effect": "event recorded", "timestamp": "2025-01-01T00:03:00Z", "agent_id": "logger-1", "tool_call_id": "tc-3", "source_file": "audit.py", "severity": "info", "detection_type": "anomaly_detection"},
        {"event_type": "incident_handling", "type": "containment", "effect": "remediation applied", "timestamp": "2025-01-01T00:04:00Z", "agent_id": "responder-1", "tool_call_id": "tc-4", "source_file": "ir.py", "response_action": "isolate"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def non_compliant_evidence(tmp_path: Path) -> Path:
    events = [
        {"event_type": "unauthorized_access", "actual_tool": "bypass_auth", "effect": "unauthorized access", "resource": "admin access granted", "policy_decision": "denied", "timestamp": "2025-01-01T00:01:00Z", "agent_id": "attacker-1", "credential_id": "stolen-cred"},
        {"event_type": "privilege_escalation", "actual_tool": "escalate", "effect": "privilege escalation detected", "resource": "wildcard permission granted", "timestamp": "2025-01-01T00:02:00Z", "agent_id": "attacker-1"},
        {"event_type": "logging_disabled", "type": "logging disabled", "effect": "no audit trail", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


def test_list_frameworks():
    frameworks = list_frameworks()
    assert "nist" in frameworks
    assert "soc2" in frameworks
    assert "iso27001" in frameworks


def test_nist_framework_has_controls():
    controls = _FRAMEWORKS["nist"]
    ids = {c["id"] for c in controls}
    assert "AC-2" in ids
    assert "AC-6" in ids
    assert "AU-2" in ids
    assert "SI-4" in ids
    assert "IR-4" in ids


def test_soc2_framework_has_controls():
    controls = _FRAMEWORKS["soc2"]
    ids = {c["id"] for c in controls}
    assert "CC6.1" in ids
    assert "CC6.3" in ids
    assert "CC7.2" in ids


def test_iso27001_framework_has_controls():
    controls = _FRAMEWORKS["iso27001"]
    ids = {c["id"] for c in controls}
    assert "A.9.2" in ids
    assert "A.12.4" in ids


def test_checker_compliant_nist(compliant_evidence: Path):
    checker = ComplianceChecker()
    report = checker.check(compliant_evidence, framework="nist")
    assert report.framework == "nist"
    assert report.total_controls == 6
    assert report.passed > 0
    assert report.overall_score > 0


def test_checker_non_compliant_nist(non_compliant_evidence: Path):
    checker = ComplianceChecker()
    report = checker.check(non_compliant_evidence, framework="nist")
    assert report.failed > 0 or report.partial > 0


def test_checker_empty_evidence(tmp_path: Path):
    checker = ComplianceChecker()
    report = checker.check(tmp_path, framework="nist")
    assert report.total_controls == 6
    for ctrl in report.controls:
        assert ctrl.status == "not-applicable"


def test_checker_soc2(compliant_evidence: Path):
    checker = ComplianceChecker()
    report = checker.check(compliant_evidence, framework="soc2")
    assert report.framework == "soc2"
    assert report.total_controls == 3


def test_checker_iso27001(compliant_evidence: Path):
    checker = ComplianceChecker()
    report = checker.check(compliant_evidence, framework="iso27001")
    assert report.framework == "iso27001"
    assert report.total_controls == 2


def test_checker_custom_rules(compliant_evidence: Path):
    custom = [
        {
            "id": "CUSTOM-1",
            "title": "Custom Control",
            "description": "Test custom rule",
            "pass_patterns": ["audit.*log"],
            "fail_patterns": ["no.*log"],
            "evidence_fields": ["event_type", "type"],
        },
    ]
    checker = ComplianceChecker()
    report = checker.check(compliant_evidence, custom_rules=custom)
    assert report.framework == "custom"
    assert report.total_controls == 1


def test_control_result_pass():
    checker = ComplianceChecker()
    ctrl = {
        "id": "TEST-1",
        "title": "Test",
        "description": "d",
        "pass_patterns": ["good"],
        "fail_patterns": ["bad"],
        "evidence_fields": ["effect"],
    }
    events = [{"effect": "good result"}, {"effect": "another good"}]
    result = checker._evaluate_control(ctrl, events)
    assert result.status == "pass"
    assert result.pass_evidence == 2
    assert result.fail_evidence == 0


def test_control_result_fail():
    checker = ComplianceChecker()
    ctrl = {
        "id": "TEST-2",
        "title": "Test",
        "description": "d",
        "pass_patterns": ["good"],
        "fail_patterns": ["bad"],
        "evidence_fields": ["effect"],
    }
    events = [{"effect": "bad outcome"}, {"effect": "very bad"}]
    result = checker._evaluate_control(ctrl, events)
    assert result.status == "fail"


def test_control_result_partial():
    checker = ComplianceChecker()
    ctrl = {
        "id": "TEST-3",
        "title": "Test",
        "description": "d",
        "pass_patterns": ["good"],
        "fail_patterns": ["bad"],
        "evidence_fields": ["effect"],
    }
    events = [
        {"effect": "good result"},
        {"effect": "good result"},
        {"effect": "good result"},
        {"effect": "bad result"},
    ]
    result = checker._evaluate_control(ctrl, events)
    assert result.status == "partial"


def test_control_result_not_applicable():
    checker = ComplianceChecker()
    ctrl = {
        "id": "TEST-4",
        "title": "Test",
        "description": "d",
        "pass_patterns": ["xyz123"],
        "fail_patterns": ["abc456"],
        "evidence_fields": ["effect"],
    }
    events = [{"effect": "nothing relevant"}]
    result = checker._evaluate_control(ctrl, events)
    assert result.status == "not-applicable"


def test_check_compliance_function(compliant_evidence: Path):
    result = check_compliance(compliant_evidence, framework="nist")
    assert isinstance(result, dict)
    assert "controls" in result
    assert "overall_score" in result


def test_format_compliance_text(compliant_evidence: Path):
    result = check_compliance(compliant_evidence, framework="nist")
    text = format_compliance_text(result)
    assert "NIST" in text
    assert "Overall Score" in text
    assert "AC-2" in text


def test_overall_score_calculation():
    checker = ComplianceChecker()
    custom = [
        {
            "id": "C1", "title": "t", "description": "d",
            "pass_patterns": ["pass"], "fail_patterns": ["fail"],
            "evidence_fields": ["type"],
        },
        {
            "id": "C2", "title": "t", "description": "d",
            "pass_patterns": ["pass"], "fail_patterns": ["fail"],
            "evidence_fields": ["type"],
        },
    ]
    events_data = [{"type": "pass event"}, {"type": "pass event"}]
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "e.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events_data), encoding="utf-8"
        )
        report = checker.check(p, custom_rules=custom)
    assert report.overall_score == 100.0


def test_report_to_dict(compliant_evidence: Path):
    checker = ComplianceChecker()
    report = checker.check(compliant_evidence, framework="nist")
    d = report.to_dict()
    assert isinstance(d, dict)
    assert isinstance(d["controls"], list)
    assert all(isinstance(c, dict) for c in d["controls"])


def test_custom_rules_from_json_file(tmp_path: Path):
    rules = [
        {
            "id": "J-1",
            "title": "JSON Rule",
            "description": "test",
            "pass_patterns": ["ok"],
            "fail_patterns": ["error"],
            "evidence_fields": ["type"],
        },
    ]
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps(rules), encoding="utf-8")

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "e.jsonl").write_text(
        json.dumps({"type": "ok event"}), encoding="utf-8"
    )

    result = check_compliance(evidence, custom_rules_path=str(rules_file))
    assert result["total_controls"] == 1
    assert result["controls"][0]["status"] == "pass"


def test_format_text_status_icons(compliant_evidence: Path):
    result = check_compliance(compliant_evidence, framework="nist")
    text = format_compliance_text(result)
    assert any(icon in text for icon in ["PASS", "FAIL", "PARTIAL", "N/A"])
