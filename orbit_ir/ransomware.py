"""Ransomware behavior pattern detection for agent incident reconstruction.

Detects patterns where agents exhibit ransomware-like behavior:
- file_encryption: mass file encryption or crypto operations
- ransom_note: creation of ransom notes or extortion messages
- shadow_deletion: deletion of backup/shadow copies
- lateral_spread: ransomware spreading to adjacent systems
- c2_ransom: command-and-control communication for ransom operations
- key_exfiltration: exfiltration of encryption keys for double extortion
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
            r"(?i)(encrypt|cipher|lock)\w*\s+(file|document|data|directory|folder|volume)",
            r"(?i)(file|document|data|directory)\w*\s+(encrypt|cipher|lock|scrambl)",
            r"(?i)(mass|bulk|batch|recursive)\s+(encrypt|cipher|lock|scrambl)",
            r"(?i)(AES|RSA|ChaCha|Salsa20|XOR)\s+(encrypt|cipher|key|operation)",
            r"(?i)(ransom|crypto)\s*(ware|locker|crypt|lock)",
        ],
        "severity": "critical",
        "description": "Mass file encryption or cryptographic locking operations",
    },
    "ransom_note": {
        "patterns": [
            r"(?i)(ransom|extortion)\s+(note|message|demand|letter|warning|notice)",
            r"(?i)(create|drop|write|place|leave)\w*\s+(ransom|extortion)\s+(note|message|file|demand)",
            r"(?i)(README|DECRYPT|RECOVER|RESTORE|HOW_TO|HELP)[-_]?(FILES|DATA|DECRYPT|RESTORE)",
            r"(?i)(bitcoin|btc|monero|xmr|cryptocurrency)\s+(address|wallet|payment|ransom)",
            r"(?i)(pay|send|transfer)\w*\s+(bitcoin|btc|monero|xmr|crypto)\w*\s+(to\s+)?(recover|decrypt|unlock)",
        ],
        "severity": "critical",
        "description": "Creation of ransom notes or extortion messages",
    },
    "shadow_deletion": {
        "patterns": [
            r"(?i)(delete|remov|destroy|wipe|clear)\w*\s+(shadow|backup|snapshot|restore\s+point|recovery)",
            r"(?i)(vssadmin|wmic)\s+(delete|destroy|resize)\s+shadow",
            r"(?i)(shadow\s+cop|backup|snapshot|restore\s+point)\w*\s+(delet|remov|destroy|wipe|disabl)",
            r"(?i)(bcdedit|wbadmin)\s+(set|delete)\s+(recoveryenabled|catalog)",
            r"(?i)(disabl|prevent)\w*\s+(recovery|restore|backup|rollback)",
        ],
        "severity": "critical",
        "description": "Deletion of backup copies, shadow copies, or recovery mechanisms",
    },
    "lateral_spread": {
        "patterns": [
            r"(?i)(spread|propagat|worm|replicate)\w*\s+(to\s+)?(adjacent|neighbor|other|remote)\s+(system|host|machine|server|network)",
            r"(?i)(lateral|network)\s+(spread|propagat|movement)\w*\s+(ransomware|malware|encrypt|payload)",
            r"(?i)(SMB|RDP|WMI|PsExec|WinRM)\s+(spread|propagat|exploit|lateral)",
            r"(?i)(self[-\s]?propagat|auto[-\s]?spread|network[-\s]?worm)",
            r"(?i)(infect|compromis)\w*\s+(additional|more|other|multiple)\s+(system|host|machine|server|endpoint)",
        ],
        "severity": "critical",
        "description": "Ransomware spreading to adjacent systems or network shares",
    },
    "c2_ransom": {
        "patterns": [
            r"(?i)(command|control|C2|C&C)\s+(server|channel|beacon|communicat)\w*\s+(ransom|encrypt|payload|key)",
            r"(?i)(ransom|encrypt)\w*\s+(command|control|C2|C&C)\s+(server|channel|beacon|communicat)",
            r"(?i)(beacon|phone\s+home|callback|check[-\s]?in)\w*\s+(ransom|encrypt|extort|operator)",
            r"(?i)(exfiltrat|upload|send)\w*\s+(victim|target)\s+(data|info|file)\w*\s+(before|prior|ahead)\s+(encrypt)",
            r"(?i)(double|triple)\s+extortion\s+(attack|scheme|campaign|operation)",
        ],
        "severity": "high",
        "description": "Command-and-control communication for ransom operations",
    },
    "key_exfiltration": {
        "patterns": [
            r"(?i)(exfiltrat|upload|send|transmit)\w*\s+(encryption|decryption|crypto)\s+(key|material|secret)",
            r"(?i)(encryption|decryption|crypto)\s+(key|material)\s+(exfiltrat|upload|send|transmit|steal)",
            r"(?i)(store|save|escrow)\w*\s+(encryption|decryption)\s+(key)\w*\s+(remote|server|C2|external)",
            r"(?i)(key\s+escrow|key\s+exchange)\w*\s+(attack|ransom|extort|malicious)",
        ],
        "severity": "high",
        "description": "Exfiltration of encryption keys for double extortion schemes",
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
                    violation_type="ransomware_behavior",
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
        score = len(cats) * 15.0 + len(agent_events) * 5.0
        if any(c in ("file_encryption", "shadow_deletion") for c in cats):
            score += 20.0
        if "ransom_note" in cats:
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
