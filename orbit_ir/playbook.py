"""Incident response playbook generator from evidence analysis."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


PLAYBOOK_KB: dict[str, dict[str, Any]] = {
    "credential_compromise": {
        "title": "Credential Compromise",
        "severity": "critical",
        "containment": [
            "Revoke all affected credentials immediately",
            "Disable compromised agent accounts",
            "Rotate API keys and tokens for affected services",
            "Block known malicious IP addresses at the network perimeter",
        ],
        "investigation": [
            "Review credential access logs for unauthorized usage",
            "Check for unauthorized API calls using compromised credentials",
            "Identify the initial credential exposure vector",
            "Map all systems accessed with compromised credentials",
        ],
        "remediation": [
            "Implement unique credentials per agent with automatic rotation",
            "Deploy a secrets manager for credential distribution",
            "Enable multi-factor authentication where supported",
            "Add credential usage anomaly detection",
        ],
        "notification": ["security_team", "credential_owners", "management"],
        "references": ["NIST 800-53 IA-5", "CIS Benchmark 5.2", "MITRE ATT&CK T1078"],
    },
    "data_exfiltration": {
        "title": "Data Exfiltration",
        "severity": "critical",
        "containment": [
            "Block outbound data transfers from compromised agents",
            "Isolate affected systems from external networks",
            "Preserve network traffic logs for forensic analysis",
            "Enable enhanced logging on data stores",
        ],
        "investigation": [
            "Identify volume and type of exfiltrated data",
            "Determine exfiltration channels (HTTP, DNS, etc.)",
            "Review data access patterns for anomalous bulk reads",
            "Check for staging directories or temporary storage",
        ],
        "remediation": [
            "Implement data loss prevention (DLP) controls",
            "Restrict agent outbound network access to allowlisted destinations",
            "Deploy egress traffic monitoring and alerting",
            "Classify and label sensitive data stores",
        ],
        "notification": ["security_team", "data_owners", "management", "legal"],
        "references": ["NIST 800-53 SC-7", "MITRE ATT&CK T1041", "MITRE ATT&CK T1048"],
    },
    "privilege_escalation": {
        "title": "Privilege Escalation",
        "severity": "critical",
        "containment": [
            "Revoke elevated privileges from compromised agents",
            "Disable accounts used for escalation",
            "Lock down privilege assignment mechanisms",
        ],
        "investigation": [
            "Review privilege assignment logs",
            "Identify the escalation technique used",
            "Check for modified access control policies",
            "Map actions taken with elevated privileges",
        ],
        "remediation": [
            "Implement least-privilege access controls for all agents",
            "Add runtime privilege monitoring and alerting",
            "Deploy just-in-time privilege elevation with approval workflows",
            "Review and harden privilege assignment policies",
        ],
        "notification": ["security_team", "management"],
        "references": ["NIST 800-53 AC-6", "MITRE ATT&CK T1078", "MITRE ATT&CK T1548"],
    },
    "lateral_movement": {
        "title": "Lateral Movement",
        "severity": "high",
        "containment": [
            "Isolate affected agents from internal networks",
            "Block inter-agent communication for compromised agents",
            "Enable enhanced logging on all agent communication channels",
        ],
        "investigation": [
            "Map the lateral movement path through the environment",
            "Identify which agents were accessed from the initial foothold",
            "Review inter-agent authentication logs",
            "Check for unauthorized service discovery activity",
        ],
        "remediation": [
            "Implement network segmentation between agent groups",
            "Deploy agent-to-agent mutual TLS authentication",
            "Restrict inter-agent communication to defined trust boundaries",
            "Add lateral movement detection rules",
        ],
        "notification": ["security_team", "ops_team"],
        "references": ["NIST 800-53 SC-7", "MITRE ATT&CK T1021", "MITRE ATT&CK T1570"],
    },
    "persistence": {
        "title": "Persistence Mechanism",
        "severity": "high",
        "containment": [
            "Identify and remove persistence artifacts",
            "Restart affected agents from known-good images",
            "Block execution of unauthorized startup scripts",
        ],
        "investigation": [
            "Search for modified configuration files",
            "Check for unauthorized scheduled tasks or cron jobs",
            "Review agent startup sequences for injected commands",
            "Examine container images for unauthorized layers",
        ],
        "remediation": [
            "Implement immutable infrastructure for agent deployments",
            "Use read-only file systems where possible",
            "Deploy file integrity monitoring on critical configs",
            "Sign and verify agent container images before deployment",
        ],
        "notification": ["security_team", "ops_team"],
        "references": ["NIST 800-53 SI-7", "MITRE ATT&CK T1053", "MITRE ATT&CK T1543"],
    },
    "command_injection": {
        "title": "Command Injection",
        "severity": "critical",
        "containment": [
            "Disable or sandbox the affected agent's tool execution",
            "Block the injection vector at the input layer",
            "Preserve command execution logs for forensics",
        ],
        "investigation": [
            "Review tool call logs for injected commands",
            "Identify the injection entry point (prompt, API, tool arg)",
            "Check for secondary payloads executed via injection",
            "Map the scope of commands executed",
        ],
        "remediation": [
            "Implement strict input validation on all tool arguments",
            "Deploy command allowlisting for agent tool execution",
            "Sandbox tool execution in restricted environments",
            "Add prompt injection detection filters",
        ],
        "notification": ["security_team", "management"],
        "references": ["OWASP LLM01", "MITRE ATT&CK T1059", "NIST 800-53 SI-10"],
    },
    "defense_evasion": {
        "title": "Defense Evasion",
        "severity": "high",
        "containment": [
            "Enable additional monitoring on evasive agents",
            "Restore tampered logging configurations",
            "Isolate agents exhibiting evasion techniques",
        ],
        "investigation": [
            "Check for gaps in log timelines indicating log tampering",
            "Review agent behavior for obfuscation patterns",
            "Identify which monitoring controls were bypassed",
            "Look for encoded or encrypted command payloads",
        ],
        "remediation": [
            "Implement tamper-proof centralized logging",
            "Deploy behavioral anomaly detection alongside signature-based rules",
            "Add integrity verification for monitoring configurations",
            "Use append-only audit logs",
        ],
        "notification": ["security_team"],
        "references": ["MITRE ATT&CK T1070", "MITRE ATT&CK T1027", "NIST 800-53 AU-9"],
    },
    "unauthorized_access": {
        "title": "Unauthorized Access",
        "severity": "high",
        "containment": [
            "Revoke unauthorized access tokens and sessions",
            "Disable affected user or agent accounts",
            "Block access from suspicious source addresses",
        ],
        "investigation": [
            "Review authentication logs for unauthorized sessions",
            "Identify which resources were accessed without authorization",
            "Check for brute-force or credential-stuffing patterns",
            "Determine if access was through a valid but stolen credential",
        ],
        "remediation": [
            "Enforce strong authentication for all agent access",
            "Implement session timeout and re-authentication policies",
            "Deploy access anomaly detection",
            "Review and tighten RBAC policies",
        ],
        "notification": ["security_team", "ops_team"],
        "references": ["NIST 800-53 AC-7", "MITRE ATT&CK T1110"],
    },
    "reconnaissance": {
        "title": "Reconnaissance Activity",
        "severity": "medium",
        "containment": [
            "Rate-limit or block reconnaissance source agents",
            "Restrict service discovery endpoints",
        ],
        "investigation": [
            "Review which services and endpoints were enumerated",
            "Identify the agent performing reconnaissance",
            "Check if reconnaissance preceded a more severe attack",
        ],
        "remediation": [
            "Minimize exposed service metadata and version information",
            "Implement rate limiting on discovery endpoints",
            "Deploy honeypots to detect reconnaissance early",
        ],
        "notification": ["security_team"],
        "references": ["MITRE ATT&CK T1595", "MITRE ATT&CK T1046"],
    },
    "resource_abuse": {
        "title": "Resource Abuse",
        "severity": "medium",
        "containment": [
            "Throttle or suspend the offending agent",
            "Apply resource quotas to limit consumption",
        ],
        "investigation": [
            "Identify which resources were consumed excessively",
            "Review cost and usage logs for anomalous spikes",
            "Determine if resource abuse was intentional or a misconfiguration",
        ],
        "remediation": [
            "Implement per-agent resource quotas and budgets",
            "Deploy cost anomaly alerting",
            "Add circuit breakers for runaway resource consumption",
        ],
        "notification": ["ops_team"],
        "references": ["NIST 800-53 SC-6"],
    },
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_DETECTION_KEYWORDS: dict[str, list[str]] = {
    "credential_compromise": ["credential", "password", "token", "api_key", "secret", "auth"],
    "data_exfiltration": ["exfiltrat", "data_leak", "bulk_read", "download", "export_data"],
    "privilege_escalation": ["privilege", "escalat", "admin", "root", "sudo", "elevat"],
    "lateral_movement": ["lateral", "pivot", "hop", "spread", "propagat"],
    "persistence": ["persist", "backdoor", "cron", "startup", "scheduled", "autorun"],
    "command_injection": ["inject", "command", "exec", "shell", "eval", "rce"],
    "defense_evasion": ["evas", "obfuscat", "tamper", "log_delet", "clear_log"],
    "unauthorized_access": ["unauthorized", "forbidden", "denied_then_allowed", "bypass"],
    "reconnaissance": ["recon", "scan", "enum", "discover", "probe", "fingerprint"],
    "resource_abuse": ["abuse", "excessive", "quota", "throttle", "overuse", "spike"],
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


def _classify_event(event: dict[str, Any]) -> list[str]:
    """Classify an event into detection types based on fields and keywords."""
    types: list[str] = []
    dt = event.get("detection_type", "")
    if dt:
        for kb_type in PLAYBOOK_KB:
            if kb_type in dt or dt in kb_type:
                types.append(kb_type)

    event_str = json.dumps(event).lower()
    for kb_type, keywords in _DETECTION_KEYWORDS.items():
        if kb_type in types:
            continue
        for kw in keywords:
            if kw in event_str:
                types.append(kb_type)
                break
    return types


def _extract_agents(events: list[dict[str, Any]]) -> list[str]:
    agents: set[str] = set()
    for e in events:
        for field in ("agent_id", "agent", "source_agent", "target_agent", "src_agent", "dst_agent"):
            v = e.get(field)
            if v and isinstance(v, str):
                agents.add(v)
    return sorted(agents)


def _extract_resources(events: list[dict[str, Any]]) -> list[str]:
    resources: set[str] = set()
    for e in events:
        for field in ("resource", "target", "file", "path", "database", "endpoint",
                       "url", "tool_name", "service", "api"):
            v = e.get(field)
            if v and isinstance(v, str):
                resources.add(v)
    return sorted(resources)


def _extract_credentials(events: list[dict[str, Any]]) -> list[str]:
    creds: set[str] = set()
    for e in events:
        for field in ("credential", "token", "api_key"):
            v = e.get(field)
            if v and isinstance(v, str):
                creds.add(v)
    return sorted(creds)


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _get_severity_level(detected_types: list[str]) -> str:
    best = "low"
    for dt in detected_types:
        kb = PLAYBOOK_KB.get(dt)
        if kb:
            sev = kb["severity"]
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(best, 0):
                best = sev
    return best


class PlaybookGenerator:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events
        self.detected_types: dict[str, int] = defaultdict(int)
        self.agents: list[str] = []
        self.resources: list[str] = []
        self.credentials: list[str] = []
        self.overall_severity = "low"
        self.first_event_time: str | None = None
        self.last_event_time: str | None = None
        self._analyze()

    def _analyze(self) -> None:
        self.agents = _extract_agents(self.events)
        self.resources = _extract_resources(self.events)
        self.credentials = _extract_credentials(self.events)

        timestamps: list[str] = []
        for e in self.events:
            ts = e.get("timestamp", "")
            if ts:
                timestamps.append(ts)
            for det_type in _classify_event(e):
                self.detected_types[det_type] += 1

        if timestamps:
            timestamps.sort()
            self.first_event_time = timestamps[0]
            self.last_event_time = timestamps[-1]

        if self.detected_types:
            self.overall_severity = _get_severity_level(list(self.detected_types.keys()))

    def generate_playbook(self, severity_threshold: str | None = None) -> dict[str, Any]:
        threshold_val = _SEVERITY_ORDER.get(severity_threshold, 0) if severity_threshold else 0

        incident_summary = {
            "overall_severity": self.overall_severity,
            "event_count": len(self.events),
            "detection_types": dict(self.detected_types),
            "first_event": self.first_event_time,
            "last_event": self.last_event_time,
        }

        affected_assets = {
            "agents": self.agents,
            "resources": self.resources[:20],
            "credentials": self.credentials[:10],
            "agent_count": len(self.agents),
            "resource_count": len(self.resources),
        }

        containment_steps: list[dict[str, Any]] = []
        investigation_steps: list[dict[str, Any]] = []
        remediation_steps: list[dict[str, Any]] = []
        notifications: set[str] = set()
        references: list[str] = []

        for det_type in sorted(self.detected_types, key=lambda t: self.detected_types[t], reverse=True):
            kb = PLAYBOOK_KB.get(det_type)
            if not kb:
                continue
            sev = kb["severity"]
            if _SEVERITY_ORDER.get(sev, 0) < threshold_val:
                continue
            count = self.detected_types[det_type]
            containment_steps.append({
                "detection_type": det_type,
                "title": kb["title"],
                "severity": sev,
                "event_count": count,
                "steps": kb["containment"],
            })
            investigation_steps.append({
                "detection_type": det_type,
                "title": kb["title"],
                "steps": kb["investigation"],
            })
            remediation_steps.append({
                "detection_type": det_type,
                "title": kb["title"],
                "steps": kb["remediation"],
            })
            for n in kb.get("notification", []):
                notifications.add(n)
            references.extend(kb.get("references", []))

        communication = _build_communication(self.overall_severity, sorted(notifications))

        post_incident = {
            "lessons_learned": [
                "Document the full incident timeline with all evidence",
                "Identify detection gaps that delayed response",
                "Review and update detection rules based on findings",
                "Conduct a blameless post-mortem with all stakeholders",
                "Update playbooks with lessons from this incident",
            ],
            "timeline_reference": {
                "first_event": self.first_event_time,
                "last_event": self.last_event_time,
                "agent_count": len(self.agents),
            },
        }

        return {
            "incident_summary": incident_summary,
            "affected_assets": affected_assets,
            "immediate_actions": containment_steps,
            "investigation_steps": investigation_steps,
            "remediation": remediation_steps,
            "communication": communication,
            "post_incident": post_incident,
            "references": sorted(set(references)),
        }

    def to_dict(self, severity_threshold: str | None = None) -> dict[str, Any]:
        return self.generate_playbook(severity_threshold=severity_threshold)


def _build_communication(severity: str, notification_targets: list[str]) -> dict[str, Any]:
    urgency_map = {
        "critical": {"urgency": "immediate", "escalation": "VP/CISO within 1 hour"},
        "high": {"urgency": "urgent", "escalation": "Security lead within 4 hours"},
        "medium": {"urgency": "normal", "escalation": "Security team within 24 hours"},
        "low": {"urgency": "informational", "escalation": "Include in weekly security report"},
    }
    comm = urgency_map.get(severity, urgency_map["low"])
    comm["notification_targets"] = notification_targets
    return comm


def generate_playbook(path: Path | str, severity_threshold: str | None = None) -> PlaybookGenerator:
    events = _load_events(Path(path))
    gen = PlaybookGenerator(events)
    gen._severity_threshold = severity_threshold  # type: ignore[attr-defined]
    return gen


def format_playbook_text(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("INCIDENT RESPONSE PLAYBOOK")
    lines.append("=" * 60)

    summary = data.get("incident_summary", {})
    lines.append("")
    lines.append("1. INCIDENT SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Severity:        {summary.get('overall_severity', 'unknown').upper()}")
    lines.append(f"  Total Events:    {summary.get('event_count', 0)}")
    lines.append(f"  First Event:     {summary.get('first_event', 'N/A')}")
    lines.append(f"  Last Event:      {summary.get('last_event', 'N/A')}")
    det = summary.get("detection_types", {})
    if det:
        lines.append(f"  Detection Types: {', '.join(f'{k} ({v})' for k, v in det.items())}")

    assets = data.get("affected_assets", {})
    lines.append("")
    lines.append("2. AFFECTED ASSETS")
    lines.append("-" * 40)
    lines.append(f"  Agents ({assets.get('agent_count', 0)}):")
    for a in assets.get("agents", [])[:10]:
        lines.append(f"    - {a}")
    lines.append(f"  Resources ({assets.get('resource_count', 0)}):")
    for r in assets.get("resources", [])[:10]:
        lines.append(f"    - {r}")
    creds = assets.get("credentials", [])
    if creds:
        lines.append(f"  Credentials ({len(creds)}):")
        for c in creds[:5]:
            lines.append(f"    - {c}")

    actions = data.get("immediate_actions", [])
    lines.append("")
    lines.append("3. IMMEDIATE ACTIONS (CONTAINMENT)")
    lines.append("-" * 40)
    for action in actions:
        lines.append(f"  [{action['severity'].upper()}] {action['title']} ({action['event_count']} events)")
        for step in action["steps"]:
            lines.append(f"    [ ] {step}")

    investigation = data.get("investigation_steps", [])
    lines.append("")
    lines.append("4. INVESTIGATION STEPS")
    lines.append("-" * 40)
    for inv in investigation:
        lines.append(f"  {inv['title']}:")
        for step in inv["steps"]:
            lines.append(f"    [ ] {step}")

    remediation = data.get("remediation", [])
    lines.append("")
    lines.append("5. REMEDIATION")
    lines.append("-" * 40)
    for rem in remediation:
        lines.append(f"  {rem['title']}:")
        for step in rem["steps"]:
            lines.append(f"    [ ] {step}")

    comm = data.get("communication", {})
    lines.append("")
    lines.append("6. COMMUNICATION")
    lines.append("-" * 40)
    lines.append(f"  Urgency:     {comm.get('urgency', 'N/A')}")
    lines.append(f"  Escalation:  {comm.get('escalation', 'N/A')}")
    targets = comm.get("notification_targets", [])
    if targets:
        lines.append(f"  Notify:      {', '.join(targets)}")

    post = data.get("post_incident", {})
    lines.append("")
    lines.append("7. POST-INCIDENT")
    lines.append("-" * 40)
    for lesson in post.get("lessons_learned", []):
        lines.append(f"  [ ] {lesson}")

    refs = data.get("references", [])
    if refs:
        lines.append("")
        lines.append("REFERENCES")
        lines.append("-" * 40)
        for ref in refs:
            lines.append(f"  - {ref}")

    lines.append("")
    return "\n".join(lines)


def format_playbook_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Incident Response Playbook")
    lines.append("")

    summary = data.get("incident_summary", {})
    lines.append("## 1. Incident Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Severity | **{summary.get('overall_severity', 'unknown').upper()}** |")
    lines.append(f"| Total Events | {summary.get('event_count', 0)} |")
    lines.append(f"| First Event | {summary.get('first_event', 'N/A')} |")
    lines.append(f"| Last Event | {summary.get('last_event', 'N/A')} |")
    lines.append("")

    assets = data.get("affected_assets", {})
    lines.append("## 2. Affected Assets")
    lines.append("")
    lines.append(f"**Agents** ({assets.get('agent_count', 0)}):")
    for a in assets.get("agents", [])[:10]:
        lines.append(f"- `{a}`")
    lines.append("")

    actions = data.get("immediate_actions", [])
    lines.append("## 3. Immediate Actions")
    lines.append("")
    for action in actions:
        lines.append(f"### {action['title']} ({action['severity'].upper()})")
        for step in action["steps"]:
            lines.append(f"- [ ] {step}")
        lines.append("")

    investigation = data.get("investigation_steps", [])
    lines.append("## 4. Investigation")
    lines.append("")
    for inv in investigation:
        lines.append(f"### {inv['title']}")
        for step in inv["steps"]:
            lines.append(f"- [ ] {step}")
        lines.append("")

    remediation = data.get("remediation", [])
    lines.append("## 5. Remediation")
    lines.append("")
    for rem in remediation:
        lines.append(f"### {rem['title']}")
        for step in rem["steps"]:
            lines.append(f"- [ ] {step}")
        lines.append("")

    comm = data.get("communication", {})
    lines.append("## 6. Communication")
    lines.append("")
    lines.append(f"- **Urgency**: {comm.get('urgency', 'N/A')}")
    lines.append(f"- **Escalation**: {comm.get('escalation', 'N/A')}")
    lines.append("")

    lines.append("## 7. Post-Incident")
    lines.append("")
    post = data.get("post_incident", {})
    for lesson in post.get("lessons_learned", []):
        lines.append(f"- [ ] {lesson}")
    lines.append("")

    return "\n".join(lines)
