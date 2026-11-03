from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


FRAMEWORK_CONTROLS: dict[str, dict[str, list[str]]] = {
    "NIST_800-53": {
        "credential_reuse": ["IA-5", "IA-6"],
        "lateral_movement": ["AC-4", "SC-7", "SI-4"],
        "privilege_escalation": ["AC-6", "AC-2"],
        "data_exfiltration": ["SC-7", "SC-28", "AU-6"],
        "command_injection": ["SI-10", "SI-3"],
        "spoofed_tool_call": ["AU-10", "SI-7"],
        "unauthorized_access": ["AC-3", "AC-6", "IA-2"],
        "anomalous_behavior": ["SI-4", "AU-6", "IR-4"],
        "coordinator_pattern": ["PM-12", "IR-5"],
        "denial_of_service": ["SC-5", "CP-7"],
        "data_tampering": ["SI-7", "AU-10"],
    },
    "SOC2_TSC": {
        "credential_reuse": ["CC6.1", "CC6.2"],
        "lateral_movement": ["CC6.1", "CC6.6"],
        "privilege_escalation": ["CC6.1", "CC6.3"],
        "data_exfiltration": ["CC6.7", "CC6.1"],
        "command_injection": ["CC6.1", "CC7.2"],
        "spoofed_tool_call": ["CC7.2", "CC8.1"],
        "unauthorized_access": ["CC6.1", "CC6.2", "CC6.3"],
        "anomalous_behavior": ["CC7.2", "CC7.3"],
        "coordinator_pattern": ["CC7.2", "CC7.4"],
        "denial_of_service": ["A1.1", "A1.2"],
        "data_tampering": ["CC7.2", "PI1.1"],
    },
    "ISO_27001": {
        "credential_reuse": ["A.9.2.4", "A.9.3.1"],
        "lateral_movement": ["A.13.1.1", "A.13.1.3"],
        "privilege_escalation": ["A.9.2.3", "A.9.4.1"],
        "data_exfiltration": ["A.13.2.1", "A.8.2.3"],
        "command_injection": ["A.14.2.5", "A.12.2.1"],
        "spoofed_tool_call": ["A.12.4.1", "A.14.1.2"],
        "unauthorized_access": ["A.9.1.1", "A.9.2.1"],
        "anomalous_behavior": ["A.12.4.1", "A.16.1.2"],
        "coordinator_pattern": ["A.16.1.4", "A.16.1.5"],
        "denial_of_service": ["A.17.1.1", "A.17.2.1"],
        "data_tampering": ["A.12.4.3", "A.14.1.3"],
    },
}

_DETECTION_ALIASES: dict[str, str] = {
    "claim_vs_check": "spoofed_tool_call",
    "oracle_integrity": "data_tampering",
    "cluster": "coordinator_pattern",
    "agent_cluster": "coordinator_pattern",
    "tool_call_spoofing": "spoofed_tool_call",
    "credential": "credential_reuse",
    "cred_reuse": "credential_reuse",
    "lateral": "lateral_movement",
    "privesc": "privilege_escalation",
    "exfil": "data_exfiltration",
    "cmd_injection": "command_injection",
    "unauth": "unauthorized_access",
    "anomaly": "anomalous_behavior",
    "dos": "denial_of_service",
    "tampering": "data_tampering",
}


@dataclass
class ControlMapping:
    control_id: str
    framework: str
    finding_count: int = 0
    finding_types: list[str] = field(default_factory=list)


@dataclass
class FrameworkSummary:
    framework: str
    total_controls: int = 0
    triggered_controls: int = 0
    coverage_pct: float = 0.0
    controls: list[ControlMapping] = field(default_factory=list)


@dataclass
class ComplianceMapResult:
    total_findings: int = 0
    frameworks: list[FrameworkSummary] = field(default_factory=list)
    unmapped_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_type(det_type: str) -> str:
    lower = det_type.lower().replace("-", "_").replace(" ", "_")
    return _DETECTION_ALIASES.get(lower, lower)


def map_compliance(
    input_path: Path,
    frameworks: list[str] | None = None,
) -> ComplianceMapResult:
    data = json.loads(input_path.read_text(encoding="utf-8"))

    findings: list[dict] = []
    if isinstance(data, dict):
        findings = data.get("findings", data.get("results", []))
    elif isinstance(data, list):
        findings = data

    if not findings:
        return ComplianceMapResult()

    type_counts: dict[str, int] = {}
    for f in findings:
        det_type = _normalize_type(
            f.get("detection_type", f.get("type", "unknown"))
        )
        type_counts[det_type] = type_counts.get(det_type, 0) + 1

    target_frameworks = frameworks or list(FRAMEWORK_CONTROLS.keys())
    unmapped: set[str] = set()
    fw_results: list[FrameworkSummary] = []

    for fw_name in target_frameworks:
        controls_map = FRAMEWORK_CONTROLS.get(fw_name, {})
        if not controls_map:
            continue

        all_controls: dict[str, set[str]] = {}
        for det_type, control_ids in controls_map.items():
            for cid in control_ids:
                if cid not in all_controls:
                    all_controls[cid] = set()

        triggered: dict[str, set[str]] = {}
        for det_type, count in type_counts.items():
            mapped = False
            ctrl_ids = controls_map.get(det_type, [])
            if ctrl_ids:
                mapped = True
                for cid in ctrl_ids:
                    if cid not in triggered:
                        triggered[cid] = set()
                    triggered[cid].add(det_type)
                    if cid not in all_controls:
                        all_controls[cid] = set()
            if not mapped:
                unmapped.add(det_type)

        ctrl_list: list[ControlMapping] = []
        for cid in sorted(all_controls.keys()):
            types_hit = sorted(triggered.get(cid, set()))
            count = sum(type_counts.get(t, 0) for t in types_hit)
            ctrl_list.append(ControlMapping(
                control_id=cid,
                framework=fw_name,
                finding_count=count,
                finding_types=types_hit,
            ))

        total = len(all_controls)
        trig = len(triggered)
        coverage = (trig / total * 100.0) if total > 0 else 0.0

        fw_results.append(FrameworkSummary(
            framework=fw_name,
            total_controls=total,
            triggered_controls=trig,
            coverage_pct=round(coverage, 1),
            controls=ctrl_list,
        ))

    return ComplianceMapResult(
        total_findings=len(findings),
        frameworks=fw_results,
        unmapped_types=sorted(unmapped),
    )


def format_compliance_map_text(result: dict) -> str:
    lines = [
        "Compliance Framework Mapping",
        "=" * 40,
        f"Total findings: {result['total_findings']}",
        "",
    ]

    for fw in result.get("frameworks", []):
        lines.append(f"  {fw['framework']}")
        lines.append(f"    Controls triggered: {fw['triggered_controls']}/{fw['total_controls']} ({fw['coverage_pct']:.1f}%)")
        triggered = [c for c in fw.get("controls", []) if c["finding_count"] > 0]
        if triggered:
            lines.append(f"    {'Control':<12} {'Findings':>8}  Types")
            lines.append("    " + "-" * 50)
            for c in triggered:
                types_str = ", ".join(c["finding_types"])
                lines.append(f"    {c['control_id']:<12} {c['finding_count']:>8}  {types_str}")
        lines.append("")

    if result.get("unmapped_types"):
        lines.append("Unmapped detection types:")
        for t in result["unmapped_types"]:
            lines.append(f"  - {t}")
        lines.append("")

    return "\n".join(lines)
