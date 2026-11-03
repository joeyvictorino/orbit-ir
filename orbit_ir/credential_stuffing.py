"""Credential stuffing and brute force detection for agent incident reconstruction.

Detects patterns where agents perform credential stuffing or brute force attacks:
- brute_force: repeated authentication attempts with different credentials
- credential_spray: trying common passwords across many accounts
- dictionary_attack: systematic password guessing using wordlists
- rate_evasion: techniques to evade rate limiting during attacks
- account_lockout: triggering account lockouts through repeated failures
- credential_reuse: using leaked/stolen credentials from other breaches
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "brute_force": {
        "patterns": [
            r"(?i)(brute\s*force|brute[-\s]?forc)\w*\s+(attack|attempt|login|auth|password|credential)",
            r"(?i)(repeated|multiple|excessive|many)\s+(login|auth|sign.in)\s+(attempt|failure|reject|denied)",
            r"(?i)(failed\s+login|auth\w*\s+failure)\s+(count|attempt|detected)\s*[>:=]\s*\d+",
            r"(?i)(systematic|automated|scripted)\s+(password|credential|login)\s+(guess|attempt|attack|test)",
        ],
        "severity": "high",
        "description": "Repeated authentication attempts with different credentials",
    },
    "credential_spray": {
        "patterns": [
            r"(?i)(credential|password)\s+(spray|spraying)\s+(attack|attempt|campaign|detected)",
            r"(?i)(spray|spraying)\w*\s+(credential|password|auth)\w*\s+(across|against|multiple)",
            r"(?i)(common|default|weak)\s+(password|credential)\w*\s+(across|against|multiple)\s+(account|user|target)",
            r"(?i)(single|one|same)\s+(password|credential)\w*\s+(many|multiple|several|all)\s+(account|user|target)",
        ],
        "severity": "high",
        "description": "Trying common passwords across many accounts simultaneously",
    },
    "dictionary_attack": {
        "patterns": [
            r"(?i)(dictionary|wordlist|word[-\s]?list)\s+(attack|attempt|based|driven|method)",
            r"(?i)(password|credential)\s+(dictionary|wordlist|list)\s+(attack|attempt|scan|test)",
            r"(?i)(rainbow\s+table|hash\s+lookup|precomputed)\s+(attack|crack|lookup|match)",
            r"(?i)(rockyou|seclists|wordlist|passlist)\s+(load|import|use|attack)",
        ],
        "severity": "high",
        "description": "Systematic password guessing using dictionary wordlists",
    },
    "rate_evasion": {
        "patterns": [
            r"(?i)(evad|bypass|circumvent|avoid)\w*\s+(rate\s*limit|throttl|lockout|cooldown|backoff)",
            r"(?i)(rate\s*limit|throttl|lockout)\w*\s+(evasi|bypass|circumvent|avoid)",
            r"(?i)(slow|low[-\s]?and[-\s]?slow|distributed|rotating)\s+(brute|attack|scan|attempt|credential)",
            r"(?i)(IP\s+rotat|proxy\s+rotat|source\s+rotat)\w*\s+(evad|bypass|avoid|distribut)",
            r"(?i)(delay|sleep|pause|wait)\w*\s+(between|before|after)\s+(attempt|request|login|auth)",
        ],
        "severity": "medium",
        "description": "Techniques to evade rate limiting during credential attacks",
    },
    "account_lockout": {
        "patterns": [
            r"(?i)(account|user)\s+(lock\s*out|locked|disabled|suspended)\s+(due\s+to|after|following)\s+(failed|repeated|excessive|multiple)",
            r"(?i)(trigger|cause|induce)\w*\s+(account|user)\s+(lock\s*out|disable|suspend|block)",
            r"(?i)(lockout|lock[-\s]?out)\s+(threshold|limit|policy|trigger)\w*\s+(reach|exceed|hit|breach)",
            r"(?i)(denial.of.service|DoS)\s+(via|through|using)\s+(account|login)\s+(lock\s*out|disable)",
        ],
        "severity": "medium",
        "description": "Triggering account lockouts through repeated authentication failures",
    },
    "credential_reuse": {
        "patterns": [
            r"(?i)(credential|password)\s+(reuse|stuffing|recycle|replay)\s+(attack|attempt|detected|campaign)",
            r"(?i)(stolen|leaked|breach|dump)\w*\s+(credential|password|combo)\w*\s+(reuse|stuff|test|try|attempt)",
            r"(?i)(combo[-\s]?list|credential[-\s]?dump|data[-\s]?breach)\w*\s+(attack|exploit|leverage|use)",
            r"(?i)(cross[-\s]?site|cross[-\s]?service|cross[-\s]?platform)\s+(credential|password)\s+(reuse|stuff|attack|test)",
        ],
        "severity": "critical",
        "description": "Using leaked or stolen credentials from other breaches",
    },
}


@dataclass
class CredentialStuffingEvent:
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
    events: list[CredentialStuffingEvent] = field(default_factory=list)


@dataclass
class CredentialStuffingChain:
    agent: str = ""
    steps: list[CredentialStuffingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class CredentialStuffingReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    chains: list[CredentialStuffingChain] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)


def _classify_event(event: dict[str, Any]) -> list[CredentialStuffingEvent]:
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
                results.append(CredentialStuffingEvent(
                    timestamp=str(event.get("timestamp", "")),
                    agent_id=str(event.get("agent_id", event.get("agent", ""))),
                    category=cat_name,
                    technique=pattern,
                    detail=combined[:200],
                    severity=cat_info["severity"],
                    policy_ref=cat_name,
                    violation_type="credential_stuffing",
                    raw=event,
                ))
                break
    return results


def _detect_chains(events: list[CredentialStuffingEvent]) -> list[CredentialStuffingChain]:
    by_agent: dict[str, list[CredentialStuffingEvent]] = defaultdict(list)
    for ev in events:
        agent = ev.agent_id or "unknown"
        by_agent[agent].append(ev)

    chains = []
    for agent, agent_events in by_agent.items():
        cats = sorted(set(e.category for e in agent_events))
        score = len(cats) * 12.0 + len(agent_events) * 5.0
        if "credential_reuse" in cats:
            score += 20.0
        if "brute_force" in cats and "rate_evasion" in cats:
            score += 15.0
        score = min(score, 100.0)
        chains.append(CredentialStuffingChain(
            agent=agent,
            steps=agent_events,
            categories_seen=cats,
            violation_score=round(score, 1),
        ))
    chains.sort(key=lambda c: c.violation_score, reverse=True)
    return chains


def analyze_credential_stuffing(events: list[dict[str, Any]]) -> CredentialStuffingReport:
    all_violations: list[CredentialStuffingEvent] = []
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

    return CredentialStuffingReport(
        total_events=len(events),
        violation_events=len(all_violations),
        categories=categories,
        chains=chains,
        agents_involved=agents,
        severity_counts=dict(sev_counts),
    )


def format_text(report: CredentialStuffingReport) -> str:
    lines = [
        "Credential Stuffing Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:  {report.total_events}",
        f"  Stuffing detections:    {report.violation_events}",
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


def format_json(report: CredentialStuffingReport) -> str:
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
