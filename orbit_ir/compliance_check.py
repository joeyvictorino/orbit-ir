"""Compliance rule evaluation against evidence.

Evaluates evidence events against compliance framework controls (NIST 800-53,
SOC 2, ISO 27001) or custom YAML rule sets. Produces per-control status
(pass / fail / partial / not-applicable).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


_FRAMEWORKS: dict[str, list[dict[str, Any]]] = {
    "nist": [
        {
            "id": "AC-2",
            "title": "Account Management",
            "description": "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
            "pass_patterns": ["account.*creat", "user.*provision", "role.*assign", "access.*grant"],
            "fail_patterns": ["unauthorized.*access", "orphan.*account", "stale.*credential"],
            "evidence_fields": ["actual_tool", "effect", "resource", "event_type"],
        },
        {
            "id": "AC-6",
            "title": "Least Privilege",
            "description": "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.",
            "pass_patterns": ["least.*privilege", "minimal.*permission", "role.*based", "scoped.*access"],
            "fail_patterns": ["admin.*access", "root.*access", "privilege.*escalat", "wildcard.*permission", "overprivilege"],
            "evidence_fields": ["actual_tool", "effect", "resource", "policy_decision"],
        },
        {
            "id": "AU-2",
            "title": "Event Logging",
            "description": "Identify events that the system is capable of logging in support of the audit function.",
            "pass_patterns": ["audit.*log", "event.*record", "logging.*enabled", "monitor"],
            "fail_patterns": ["logging.*disabled", "no.*audit", "unmonitored"],
            "evidence_fields": ["event_type", "type", "effect"],
        },
        {
            "id": "AU-3",
            "title": "Content of Audit Records",
            "description": "Ensure audit records contain sufficient information to establish what events occurred.",
            "pass_patterns": ["timestamp", "agent_id", "tool_call_id", "source_file"],
            "fail_patterns": ["missing.*timestamp", "no.*agent.*id", "incomplete.*record"],
            "evidence_fields": ["timestamp", "agent_id", "tool_call_id", "source_file"],
        },
        {
            "id": "SI-4",
            "title": "System Monitoring",
            "description": "Monitor the system to detect attacks and indicators of potential attacks.",
            "pass_patterns": ["monitor", "detect", "alert", "anomaly.*detect", "intrusion"],
            "fail_patterns": ["unmonitored", "no.*detection", "blind.*spot"],
            "evidence_fields": ["event_type", "type", "detection_type", "severity"],
        },
        {
            "id": "IR-4",
            "title": "Incident Handling",
            "description": "Implement an incident handling capability that includes preparation, detection, analysis, containment, eradication, and recovery.",
            "pass_patterns": ["incident.*handl", "containment", "remediat", "recover", "response.*plan"],
            "fail_patterns": ["no.*response", "uncontained", "spread.*unchecked"],
            "evidence_fields": ["event_type", "type", "effect", "response_action"],
        },
    ],
    "soc2": [
        {
            "id": "CC6.1",
            "title": "Logical and Physical Access Controls",
            "description": "Logical access security software, infrastructure, and architectures have been implemented.",
            "pass_patterns": ["access.*control", "authenticat", "authoriz", "credential.*valid", "policy.*enforc"],
            "fail_patterns": ["bypass.*auth", "no.*authentication", "open.*access", "unauthenticated"],
            "evidence_fields": ["actual_tool", "policy_decision", "credential_id", "effect"],
        },
        {
            "id": "CC6.3",
            "title": "Role-Based Access and Least Privilege",
            "description": "Role-based access controls are in place and access is restricted to authorized users.",
            "pass_patterns": ["role.*based", "rbac", "least.*privilege", "permission.*check"],
            "fail_patterns": ["privilege.*escalat", "unauthorized.*role", "admin.*default"],
            "evidence_fields": ["actual_tool", "effect", "resource", "role"],
        },
        {
            "id": "CC7.2",
            "title": "Monitoring of System Components",
            "description": "The entity monitors system components and the operation of those components for anomalies.",
            "pass_patterns": ["monitor", "anomaly", "alert", "surveillance", "detection"],
            "fail_patterns": ["unmonitored", "no.*alert", "silent.*failure"],
            "evidence_fields": ["event_type", "type", "severity", "detection_type"],
        },
    ],
    "iso27001": [
        {
            "id": "A.9.2",
            "title": "User Access Management",
            "description": "Ensure authorized user access and prevent unauthorized access to systems and services.",
            "pass_patterns": ["user.*access", "provision", "deprovisio", "access.*review", "authenticat"],
            "fail_patterns": ["unauthorized", "orphan.*account", "shared.*credential"],
            "evidence_fields": ["actual_tool", "credential_id", "agent_id", "policy_decision"],
        },
        {
            "id": "A.12.4",
            "title": "Logging and Monitoring",
            "description": "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
            "pass_patterns": ["log", "audit.*trail", "event.*record", "monitor"],
            "fail_patterns": ["no.*log", "logging.*disabled", "missing.*audit"],
            "evidence_fields": ["timestamp", "event_type", "type", "source_file"],
        },
    ],
}


@dataclass
class ControlResult:
    control_id: str
    title: str
    description: str
    status: str  # pass, fail, partial, not-applicable
    pass_evidence: int = 0
    fail_evidence: int = 0
    total_checked: int = 0
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceReport:
    framework: str
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_applicable: int = 0
    controls: list[ControlResult] = field(default_factory=list)
    overall_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["controls"] = [c.to_dict() for c in self.controls]
        return d


class ComplianceChecker:
    def __init__(self) -> None:
        pass

    def check(
        self,
        evidence_dir: str | Path,
        framework: str = "nist",
        custom_rules: list[dict[str, Any]] | None = None,
    ) -> ComplianceReport:
        evidence_dir = Path(evidence_dir)
        events = _load_events(evidence_dir) if evidence_dir.exists() else []

        if custom_rules is not None:
            controls_def = custom_rules
            fw_name = "custom"
        else:
            fw_name = framework.lower()
            controls_def = _FRAMEWORKS.get(fw_name, [])

        results: list[ControlResult] = []
        for ctrl in controls_def:
            result = self._evaluate_control(ctrl, events)
            results.append(result)

        passed = sum(1 for r in results if r.status == "pass")
        failed = sum(1 for r in results if r.status == "fail")
        partial = sum(1 for r in results if r.status == "partial")
        na = sum(1 for r in results if r.status == "not-applicable")
        total = len(results)
        score = (passed + partial * 0.5) / total * 100 if total > 0 else 0.0

        return ComplianceReport(
            framework=fw_name,
            total_controls=total,
            passed=passed,
            failed=failed,
            partial=partial,
            not_applicable=na,
            controls=results,
            overall_score=round(score, 1),
        )

    def _evaluate_control(
        self,
        ctrl: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> ControlResult:
        ctrl_id = ctrl.get("id", "unknown")
        title = ctrl.get("title", "")
        description = ctrl.get("description", "")
        pass_patterns = [re.compile(p, re.IGNORECASE) for p in ctrl.get("pass_patterns", [])]
        fail_patterns = [re.compile(p, re.IGNORECASE) for p in ctrl.get("fail_patterns", [])]
        evidence_fields = ctrl.get("evidence_fields", [])

        pass_count = 0
        fail_count = 0
        relevant = 0

        for event in events:
            field_values: list[str] = []
            for f in evidence_fields:
                v = event.get(f, "")
                if isinstance(v, str) and v:
                    field_values.append(v)

            if not field_values:
                continue

            text = " ".join(field_values)
            has_pass = any(p.search(text) for p in pass_patterns)
            has_fail = any(p.search(text) for p in fail_patterns)

            if has_pass or has_fail:
                relevant += 1
                if has_pass:
                    pass_count += 1
                if has_fail:
                    fail_count += 1

        if relevant == 0:
            status = "not-applicable"
            details = "No relevant evidence found"
        elif fail_count == 0 and pass_count > 0:
            status = "pass"
            details = f"{pass_count} supporting evidence items found"
        elif fail_count > 0 and pass_count == 0:
            status = "fail"
            details = f"{fail_count} violation indicators found"
        else:
            ratio = pass_count / (pass_count + fail_count) if (pass_count + fail_count) > 0 else 0
            if ratio >= 0.7:
                status = "partial"
                details = f"{pass_count} supporting, {fail_count} violations (mostly compliant)"
            else:
                status = "fail"
                details = f"{pass_count} supporting, {fail_count} violations"

        return ControlResult(
            control_id=ctrl_id,
            title=title,
            description=description,
            status=status,
            pass_evidence=pass_count,
            fail_evidence=fail_count,
            total_checked=relevant,
            details=details,
        )


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events


def _load_custom_rules(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            return yaml.safe_load(text)
        except ImportError:
            pass
    data = json.loads(text)
    if isinstance(data, list):
        return data
    return data.get("controls", data.get("rules", []))


def check_compliance(
    evidence_dir: str | Path,
    framework: str = "nist",
    custom_rules_path: str | Path | None = None,
) -> dict[str, Any]:
    custom = None
    if custom_rules_path:
        custom = _load_custom_rules(Path(custom_rules_path))
    checker = ComplianceChecker()
    report = checker.check(evidence_dir, framework=framework, custom_rules=custom)
    return report.to_dict()


def format_compliance_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    fw = result.get("framework", "unknown").upper()
    lines.append(f"Compliance Check: {fw}")
    lines.append(f"  Overall Score: {result.get('overall_score', 0)}%")
    lines.append(
        f"  Controls: {result['total_controls']} total — "
        f"{result['passed']} pass, {result['failed']} fail, "
        f"{result['partial']} partial, {result['not_applicable']} n/a"
    )
    lines.append("")

    status_icon = {"pass": "PASS", "fail": "FAIL", "partial": "PARTIAL", "not-applicable": "N/A"}

    for ctrl in result.get("controls", []):
        icon = status_icon.get(ctrl["status"], "?")
        lines.append(f"  [{icon:>7}] {ctrl['control_id']}: {ctrl['title']}")
        lines.append(f"           {ctrl['details']}")

    lines.append("")
    return "\n".join(lines) + "\n"


def list_frameworks() -> list[str]:
    return sorted(_FRAMEWORKS.keys())
