"""Ransomware behavior detection for agent incident reconstruction.

Detects patterns where agents exhibit ransomware-like behavior:
- file_encryption: mass file encryption or cryptographic operations on user data
- ransom_note: ransom note creation, display, or delivery
- shadow_deletion: volume shadow copy or backup deletion
- privilege_escalation: privilege escalation preceding encryption
- network_propagation: lateral movement and self-propagation via network
- exfiltration_threat: data exfiltration for double-extortion schemes
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "file_encryption": {
        "patterns": [
            r"(?i)(encrypt|cipher|crypto)\w*\s+(file|document|data|directory|folder)\w*\s+(mass|bulk|recursive|detected|operation)",
            r"(?i)(file|document|data)\w*\s+(encrypt|cipher|lock)\w*\s+(detect|mass|bulk|ransom|recursive)",
            r"(?i)(AES|RSA|ChaCha|Salsa)\s+(encrypt|cipher)\w*\s+(file|document|data|payload|operation)",
            r"(?i)(ransomware|crypto.?locker|file.?crypt)\w*\s+(encrypt|lock|attack|detect|payload)",
        ],
        "severity": "critical",
        "description": "Mass file encryption or cryptographic operations on user data",
    },
    "ransom_note": {
        "patterns": [
            r"(?i)(ransom|extort)\w*\s+(note|message|demand|instruction)\w*\s+(creat|deliver|display|drop|detect)",
            r"(?i)(README|DECRYPT|RECOVER|RESTORE|HOW.TO)\w*\s+(ransom|decrypt|payment|bitcoin|instruction)",
            r"(?i)(creat|deliver|drop|display|detect)\w*\s+(ransom|extort)\w*\s+(note|message|demand|file)",
            r"(?i)(payment|bitcoin|crypto)\w*\s+(demand|instruct|address)\w*\s+(ransom|extort|decrypt|recover)",
        ],
        "severity": "critical",
        "description": "Ransom note creation, display, or delivery to victims",
    },
    "shadow_deletion": {
        "patterns": [
            r"(?i)(shadow|VSS|volume.shadow)\w*\s+(copy|snapshot|backup)\w*\s+(delet|remov|destroy|wipe|disabl)",
            r"(?i)(delet|remov|destroy|wipe|disabl)\w*\s+(shadow|VSS|volume.shadow|backup|snapshot)\w*\s+(copy|volume|detect)",
            r"(?i)(vssadmin|wmic|bcdedit)\w*\s+(delete|shadows|recoveryenabled)\w*\s+(shadow|backup|false|detect)",
            r"(?i)(backup|recovery|restore)\w*\s+(delet|disabl|destroy|prevent|wipe)\w*\s+(detect|system|point|volume)",
        ],
        "severity": "critical",
        "description": "Volume shadow copy or backup deletion to prevent recovery",
    },
    "privilege_escalation": {
        "patterns": [
            r"(?i)(privilege|privesc|escalat)\w*\s+(escalat|elevat|gain|exploit)\w*\s+(detect|admin|root|system|before.encrypt)",
            r"(?i)(escalat|elevat|gain)\w*\s+(privilege|admin|root|SYSTEM)\w*\s+(access|right|permission)\w*\s+(detect|exploit|ransom)",
            r"(?i)(exploit|vuln|CVE)\w*\s+(privilege|escalat|elevat)\w*\s+(detect|local|kernel|ransom)",
            r"(?i)(UAC|sudo|setuid)\w*\s+(bypass|exploit|abuse)\w*\s+(detect|escalat|privilege|ransom)",
        ],
        "severity": "high",
        "description": "Privilege escalation preceding ransomware encryption",
    },
    "network_propagation": {
        "patterns": [
            r"(?i)(ransomware|malware|worm)\w*\s+(propagat|spread|lateral|replicate)\w*\s+(network|SMB|share|detect)",
            r"(?i)(lateral|network)\w*\s+(movement|propagat|spread)\w*\s+(ransomware|encrypt|malware|detect)",
            r"(?i)(SMB|RDP|WMI|PsExec)\w*\s+(propagat|spread|exploit|lateral)\w*\s+(ransomware|encrypt|detect|network)",
            r"(?i)(self.?propagat|worm.?like|auto.?spread)\w*\s+(ransomware|encrypt|malware|behavior)\w*\s+(detect|network|lateral)",
        ],
        "severity": "high",
        "description": "Lateral movement and self-propagation of ransomware via network",
    },
    "exfiltration_threat": {
        "patterns": [
            r"(?i)(exfiltrat|steal|extract)\w*\s+(data|file|document)\w*\s+(before|prior|ransomware|encrypt|extort)",
            r"(?i)(double|triple)\s+(extort|ransom)\w*\s+(detect|scheme|attack|threat|data)",
            r"(?i)(data|file)\w*\s+(theft|exfiltrat|steal)\w*\s+(extort|ransom|leverage|threaten|detect)",
            r"(?i)(threaten|leverage)\w*\s+(publish|leak|release|expose)\w*\s+(stolen|exfiltrat|data|file)\w*\s+(ransom|extort|detect)",
        ],
        "severity": "high",
        "description": "Data exfiltration for double-extortion ransomware schemes",
    },
}


@dataclass
class RansomwareEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    policy_ref: str = ""
    violation_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[RansomwareEvent] = field(default_factory=list)


@dataclass
class RansomwareChain:
    agent: str = ""
    steps: list[RansomwareEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class RansomwareReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    chains: list[RansomwareChain] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)


def _classify_event(event: dict[str, Any]) -> list[RansomwareEvent]:
    results = []
    text_fields = []
    for key in ("action", "detail", "description", "message", "summary", "command", "output", "content"):
        val = event.get(key, "")
        if isinstance(val, str) and val:
            text_fields.append(val)
    combined = " ".join(text_fields)
    if not combined.strip():
        return results

    for cat_name, cat_info in CATEGORIES.items():
        for pattern in cat_info["patterns"]:
            if re.search(pattern, combined):
                results.append(RansomwareEvent(
                    timestamp=str(event.get("timestamp", "")),
                    agent_id=str(event.get("agent_id", event.get("agent", ""))),
                    category=cat_name,
                    technique=pattern,
                    detail=combined[:200],
                    severity=cat_info["severity"],
                    policy_ref=cat_name,
                    violation_type="ransomware_activity",
                    raw=event,
                ))
                break
    return results


def _detect_chains(events: list[RansomwareEvent]) -> list[RansomwareChain]:
    by_agent: dict[str, list[RansomwareEvent]] = defaultdict(list)
    for ev in events:
        agent = ev.agent_id or "unknown"
        by_agent[agent].append(ev)

    chains = []
    for agent, agent_events in by_agent.items():
        cats = sorted(set(e.category for e in agent_events))
        score = len(cats) * 12.0 + len(agent_events) * 5.0
        if "file_encryption" in cats and "ransom_note" in cats:
            score += 25.0
        if "shadow_deletion" in cats:
            score += 20.0
        if "exfiltration_threat" in cats:
            score += 15.0
        score = min(score, 100.0)
        chains.append(RansomwareChain(
            agent=agent,
            steps=agent_events,
            categories_seen=cats,
            violation_score=round(score, 1),
        ))
    chains.sort(key=lambda c: c.violation_score, reverse=True)
    return chains


def analyze_ransomware(events: list[dict[str, Any]]) -> RansomwareReport:
    all_violations: list[RansomwareEvent] = []
    for event in events:
        all_violations.extend(_classify_event(event))

    cat_map: dict[str, CategorySummary] = {}
    for ev in all_violations:
        if ev.category not in cat_map:
            info = CATEGORIES.get(ev.category, {})
            cat_map[ev.category] = CategorySummary(
                category=ev.category,
                description=info.get("description", ""),
                count=0,
                severity=info.get("severity", "medium"),
            )
        cat_map[ev.category].count += 1
        cat_map[ev.category].events.append(ev)

    categories = sorted(cat_map.values(), key=lambda c: c.count, reverse=True)
    chains = _detect_chains(all_violations)
    agents = sorted(set(e.agent_id for e in all_violations if e.agent_id))
    sev_counts: dict[str, int] = defaultdict(int)
    for ev in all_violations:
        sev_counts[ev.severity] += 1

    return RansomwareReport(
        total_events=len(events),
        violation_events=len(all_violations),
        categories=categories,
        chains=chains,
        agents_involved=agents,
        severity_counts=dict(sev_counts),
    )


def format_text(report: RansomwareReport) -> str:
    lines = [
        "Ransomware Behavior Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:  {report.total_events}",
        f"  Ransomware detections:  {report.violation_events}",
        f"  Agents involved:        {len(report.agents_involved)}",
        f"  Attack chains:          {len(report.chains)}",
        "",
    ]
    if report.severity_counts:
        lines.append("  Severity breakdown:")
        for sev in ("critical", "high", "medium", "low"):
            if sev in report.severity_counts:
                lines.append(f"    {sev}: {report.severity_counts[sev]}")
        lines.append("")

    if report.categories:
        lines.append("  Categories:")
        for cat in report.categories:
            lines.append(f"    [{cat.severity}] {cat.category}: {cat.count} events")
            lines.append(f"      {cat.description}")
        lines.append("")

    if report.chains:
        lines.append("  Attack chains:")
        for chain in report.chains:
            lines.append(f"    Agent: {chain.agent}  score={chain.violation_score}")
            lines.append(f"      categories: {', '.join(chain.categories_seen)}")
            lines.append(f"      steps: {len(chain.steps)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: RansomwareReport) -> str:
    data = {
        "total_events": report.total_events,
        "violation_events": report.violation_events,
        "agents_involved": report.agents_involved,
        "severity_counts": report.severity_counts,
        "categories": [
            {"category": c.category, "description": c.description, "count": c.count, "severity": c.severity}
            for c in report.categories
        ],
        "chains": [
            {"agent": ch.agent, "categories_seen": ch.categories_seen,
             "violation_score": ch.violation_score, "steps": len(ch.steps)}
            for ch in report.chains
        ],
    }
    return json.dumps(data, indent=2) + "\n"


def _load_events(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    with open(p) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]
