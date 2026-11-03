"""Remediation suggestion generator for detected incidents."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


REMEDIATION_KB: dict[str, dict[str, Any]] = {
    "credential_reuse": {
        "title": "Credential Reuse Detected",
        "severity": "high",
        "steps": [
            "Rotate all affected credentials immediately",
            "Implement unique credentials per agent",
            "Deploy a secrets manager for credential distribution",
            "Enable credential usage auditing",
        ],
        "references": ["CIS Benchmark 5.2", "NIST 800-53 IA-5"],
    },
    "privilege_escalation": {
        "title": "Privilege Escalation Detected",
        "severity": "critical",
        "steps": [
            "Revoke elevated privileges from compromised agents",
            "Review and restrict privilege assignment policies",
            "Implement least-privilege access controls",
            "Add runtime privilege monitoring",
        ],
        "references": ["NIST 800-53 AC-6", "MITRE ATT&CK T1078"],
    },
    "lateral_movement": {
        "title": "Lateral Movement Detected",
        "severity": "high",
        "steps": [
            "Isolate affected agents from the network",
            "Review and restrict inter-agent communication policies",
            "Implement network segmentation between agent groups",
            "Deploy agent-to-agent authentication",
        ],
        "references": ["NIST 800-53 SC-7", "MITRE ATT&CK T1021"],
    },
    "data_exfiltration": {
        "title": "Data Exfiltration Detected",
        "severity": "critical",
        "steps": [
            "Block outbound data transfer from compromised agents",
            "Identify and classify exfiltrated data",
            "Implement data loss prevention (DLP) controls",
            "Review and restrict agent outbound network access",
        ],
        "references": ["NIST 800-53 SC-7", "MITRE ATT&CK T1041"],
    },
    "unauthorized_access": {
        "title": "Unauthorized Access Detected",
        "severity": "high",
        "steps": [
            "Revoke unauthorized access tokens",
            "Review access control lists for affected resources",
            "Implement multi-factor authentication for sensitive operations",
            "Enable access logging and alerting",
        ],
        "references": ["NIST 800-53 AC-2", "CIS Benchmark 6.2"],
    },
    "command_injection": {
        "title": "Command Injection Detected",
        "severity": "critical",
        "steps": [
            "Sandbox affected agent execution environments",
            "Implement input validation and sanitization",
            "Restrict agent command execution capabilities",
            "Deploy allowlisted command execution policies",
        ],
        "references": ["OWASP A03:2021", "NIST 800-53 SI-10"],
    },
    "persistence": {
        "title": "Persistence Mechanism Detected",
        "severity": "high",
        "steps": [
            "Identify and remove persistence artifacts",
            "Reset agent configurations to known-good state",
            "Implement configuration integrity monitoring",
            "Deploy file integrity monitoring on agent runtimes",
        ],
        "references": ["MITRE ATT&CK T1053", "NIST 800-53 SI-7"],
    },
    "defense_evasion": {
        "title": "Defense Evasion Detected",
        "severity": "high",
        "steps": [
            "Review and strengthen monitoring coverage",
            "Implement tamper-resistant logging",
            "Deploy behavioral analysis alongside signature detection",
            "Enable immutable audit trails",
        ],
        "references": ["MITRE ATT&CK T1562", "NIST 800-53 AU-9"],
    },
    "tool_name_mismatch": {
        "title": "Tool Name Mismatch (Spoofed Tool Call)",
        "severity": "high",
        "steps": [
            "Verify tool call provenance and authenticity",
            "Implement tool call signing and verification",
            "Review agent tool access permissions",
            "Deploy tool call audit logging",
        ],
        "references": ["NIST 800-53 SI-7", "MITRE ATT&CK T1036"],
    },
    "unbacked_completion": {
        "title": "Unbacked Completion (Hallucinated Response)",
        "severity": "medium",
        "steps": [
            "Implement response verification against source data",
            "Deploy grounding checks for agent outputs",
            "Add confidence scoring to agent responses",
            "Implement human-in-the-loop for high-stakes outputs",
        ],
        "references": ["NIST AI RMF MEASURE 2.6", "OWASP LLM01"],
    },
    "anomalous_behavior": {
        "title": "Anomalous Agent Behavior Pattern",
        "severity": "medium",
        "steps": [
            "Investigate root cause of behavioral deviation",
            "Compare agent behavior against established baseline",
            "Consider quarantining agent pending investigation",
            "Review recent configuration or model changes",
        ],
        "references": ["NIST 800-53 SI-4", "NIST AI RMF MEASURE 2.7"],
    },
    "data_poisoning": {
        "title": "Potential Data Poisoning Detected",
        "severity": "critical",
        "steps": [
            "Isolate affected training or retrieval data stores",
            "Validate data integrity against known-good checksums",
            "Review data ingestion pipeline for injection points",
            "Implement data provenance tracking",
        ],
        "references": ["NIST AI RMF MAP 1.5", "MITRE ATLAS AML.T0020"],
    },
}

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_DETECTION_KEYWORDS: dict[str, list[str]] = {
    "credential_reuse": ["credential", "reuse", "shared_secret", "same_token", "same_password"],
    "privilege_escalation": ["privilege", "escalation", "escalat", "sudo", "root", "admin"],
    "lateral_movement": ["lateral", "movement", "pivot", "hop", "propagat"],
    "data_exfiltration": ["exfiltrat", "data_theft", "steal", "upload_data", "transfer_out"],
    "unauthorized_access": ["unauthorized", "forbidden", "access_denied", "invalid_token", "no_permission"],
    "command_injection": ["injection", "inject", "command_exec", "rce", "code_execution"],
    "persistence": ["persistence", "persist", "backdoor", "implant", "scheduled_task", "cron"],
    "defense_evasion": ["evasion", "evas", "obfuscat", "masquerade", "disable_log"],
    "tool_name_mismatch": ["tool-name-mismatch", "tool_name_mismatch", "spoofed", "mismatch"],
    "unbacked_completion": ["unbacked", "hallucin", "ungrounded", "unsupported_claim"],
    "anomalous_behavior": ["anomal", "unusual", "deviat", "outlier", "abnormal"],
    "data_poisoning": ["poison", "corrupt", "tamper", "inject_data"],
}


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


def _classify_event(event: dict[str, Any]) -> set[str]:
    detected: set[str] = set()
    text = json.dumps(event).lower()

    det_type = event.get("detection_type", "")
    if isinstance(det_type, str):
        for key in REMEDIATION_KB:
            if key.replace("_", "-") == det_type or key == det_type:
                detected.add(key)

    for key, keywords in _DETECTION_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                detected.add(key)
                break

    return detected


class RemediationGenerator:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.suggestions: list[dict[str, Any]] = []

    def load_events(self, path: Path) -> None:
        self.events = _load_events(path)

    def analyze(self) -> None:
        detection_agents: dict[str, set[str]] = defaultdict(set)
        detection_counts: dict[str, int] = defaultdict(int)

        for event in self.events:
            types = _classify_event(event)
            agents: set[str] = set()
            for key in ("agent_id", "agent", "src_agent"):
                v = event.get(key)
                if isinstance(v, str) and v:
                    agents.add(v)

            for dt in types:
                detection_counts[dt] += 1
                detection_agents[dt].update(agents)

        suggestions: list[dict[str, Any]] = []
        for dt, count in detection_counts.items():
            kb = REMEDIATION_KB.get(dt)
            if not kb:
                continue
            agents_list = sorted(detection_agents[dt])
            sev = kb["severity"]
            sev_weight = _SEVERITY_WEIGHT.get(sev, 1)
            priority = sev_weight * max(len(agents_list), 1)
            suggestions.append({
                "detection_type": dt,
                "title": kb["title"],
                "severity": sev,
                "event_count": count,
                "affected_agents": agents_list,
                "steps": kb["steps"],
                "references": kb["references"],
                "priority": priority,
            })

        suggestions.sort(key=lambda s: (-s["priority"], s["detection_type"]))
        self.suggestions = suggestions

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": len(self.events),
            "suggestion_count": len(self.suggestions),
            "suggestions": self.suggestions,
        }


def generate_remediations(
    path: Path,
    severity_filter: str | None = None,
) -> RemediationGenerator:
    gen = RemediationGenerator()
    gen.load_events(path)
    gen.analyze()

    if severity_filter:
        min_weight = _SEVERITY_WEIGHT.get(severity_filter.lower(), 0)
        gen.suggestions = [
            s for s in gen.suggestions
            if _SEVERITY_WEIGHT.get(s["severity"], 0) >= min_weight
        ]

    return gen


def format_remediate_text(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Remediation Report ({data['suggestion_count']} suggestions from {data['total_events']} events)")
    lines.append("")

    if not data["suggestions"]:
        lines.append("No actionable remediations identified.")
        return "\n".join(lines) + "\n"

    for i, s in enumerate(data["suggestions"], 1):
        lines.append(f"{i}. [{s['severity'].upper()}] {s['title']} (priority: {s['priority']})")
        lines.append(f"   Detection: {s['detection_type']} ({s['event_count']} events)")
        if s["affected_agents"]:
            lines.append(f"   Affected agents: {', '.join(s['affected_agents'])}")
        lines.append("   Steps:")
        for step in s["steps"]:
            lines.append(f"     - {step}")
        if s["references"]:
            lines.append(f"   References: {', '.join(s['references'])}")
        lines.append("")

    return "\n".join(lines) + "\n"
