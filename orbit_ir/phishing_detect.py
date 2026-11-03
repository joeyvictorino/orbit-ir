"""Phishing and social engineering attack detection for agent incident reconstruction.

Detects patterns where agents perform phishing or social engineering attacks:
- spear_phishing: targeted phishing, impersonation, pretexting
- url_manipulation: typosquatting, URL obfuscation, homograph attacks
- credential_phish: fake login pages, credential harvesting via phishing
- watering_hole: compromised trusted sites, drive-by downloads
- vishing_smishing: voice/SMS phishing, phone-based social engineering
- bec_fraud: business email compromise, CEO fraud, invoice fraud
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "spear_phishing": {
        "patterns": [
            r"(?i)(spear\s*phish|targeted\s+phish)\w*\s+(attack|campaign|attempt|email|message)",
            r"(?i)(impersonat|pretexting|social\s+engineer)\w*\s+(attack|attempt|campaign|scheme|tactic)",
            r"(?i)(phishing|phish)\w*\s+(target|victim|employee|executive|user)\w*\s+(with|using|via|through)",
            r"(?i)(craft|create|send)\w*\s+(phishing|spear.phish|deceptive)\s+(email|message|lure)",
        ],
        "severity": "critical",
        "description": "Targeted phishing attacks using impersonation or pretexting",
    },
    "url_manipulation": {
        "patterns": [
            r"(?i)(typosquat|homograph|punycode)\w*\s+(attack|domain|URL|link)",
            r"(?i)(URL|link|domain)\s+(obfuscat|manipulat|spoof|disguise)\w*\s+(attack|attempt|detect)",
            r"(?i)(fake|malicious|deceptive)\s+(URL|link|domain|website)\s+(redirect|created|register)",
            r"(?i)(lookalike|similar|confus)\w*\s+(domain|URL|website|link)\s+(register|created|detect)",
        ],
        "severity": "high",
        "description": "URL obfuscation, typosquatting, and homograph attacks",
    },
    "credential_phish": {
        "patterns": [
            r"(?i)(fake|phishing|fraudulent)\s+(login|sign.in|auth\w*)\s+(page|form|portal|site)",
            r"(?i)(credential|password)\s+(harvest|phish|steal|capture)\w*\s+(via|through|using)\s+(phish|fake|fraudulent)",
            r"(?i)(clone|replica|mirror)\w*\s+(login|auth\w*|sign.in)\s+(page|portal|site|form)",
            r"(?i)(capture|intercept|steal)\w*\s+(credential|password|token)\w*\s+(phishing|fake\s+page|decept)",
        ],
        "severity": "high",
        "description": "Fake login pages and credential harvesting via phishing",
    },
    "watering_hole": {
        "patterns": [
            r"(?i)(watering\s*hole|water.hole)\s+(attack|compromise|campaign|strategy)",
            r"(?i)(compromis|infect|inject)\w*\s+(trusted|legitimate|popular)\s+(site|website|resource|page)",
            r"(?i)(drive.by|driveby)\s+(download|exploit|attack)\s+(via|through|from)\s+(trusted|compromised)",
            r"(?i)(strategic\s+web|targeted\s+web)\s+(compromise|attack|infection)",
        ],
        "severity": "high",
        "description": "Compromised trusted sites and drive-by download attacks",
    },
    "vishing_smishing": {
        "patterns": [
            r"(?i)(vishing|voice\s+phish)\w*\s+(attack|attempt|call|campaign|scam)",
            r"(?i)(smishing|SMS\s+phish)\w*\s+(attack|attempt|message|campaign)",
            r"(?i)(phone|voice|call|SMS|text)\s+(based|driven)?\s*(phish|scam|fraud|social\s+engineer)",
            r"(?i)(pretend|impersonat)\w*\s+(call|phone|voice|SMS)\w*\s+(support|bank|IT|helpdesk)",
        ],
        "severity": "medium",
        "description": "Voice and SMS phishing attacks",
    },
    "bec_fraud": {
        "patterns": [
            r"(?i)(business\s+email\s+compromise|BEC)\s+(attack|fraud|scheme|campaign|attempt)",
            r"(?i)(CEO|CFO|executive)\s+(fraud|impersonat|spoof)\w*\s+(email|wire|transfer|payment)",
            r"(?i)(invoice|payment|wire\s+transfer)\s+(fraud|redirect|diversion|manipulat)\w*\s+(attack|scheme|attempt)",
            r"(?i)(account\s+takeover|email\s+takeover)\w*\s+(for|to)\s+(fraud|payment|invoice|wire)",
        ],
        "severity": "critical",
        "description": "Business email compromise and invoice fraud",
    },
}


@dataclass
class PhishingEvent:
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
    events: list[PhishingEvent] = field(default_factory=list)


@dataclass
class PhishingChain:
    agent: str = ""
    steps: list[PhishingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class PhishingReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    chains: list[PhishingChain] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)


def _classify_event(event: dict[str, Any]) -> list[PhishingEvent]:
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
                results.append(PhishingEvent(
                    timestamp=str(event.get("timestamp", "")),
                    agent_id=str(event.get("agent_id", event.get("agent", ""))),
                    category=cat_name,
                    technique=pattern,
                    detail=combined[:200],
                    severity=cat_info["severity"],
                    policy_ref=cat_name,
                    violation_type="phishing_attack",
                    raw=event,
                ))
                break
    return results


def _detect_chains(events: list[PhishingEvent]) -> list[PhishingChain]:
    by_agent: dict[str, list[PhishingEvent]] = defaultdict(list)
    for ev in events:
        agent = ev.agent_id or "unknown"
        by_agent[agent].append(ev)

    chains = []
    for agent, agent_events in by_agent.items():
        cats = sorted(set(e.category for e in agent_events))
        score = len(cats) * 12.0 + len(agent_events) * 5.0
        if "spear_phishing" in cats and "credential_phish" in cats:
            score += 20.0
        if "bec_fraud" in cats:
            score += 15.0
        score = min(score, 100.0)
        chains.append(PhishingChain(
            agent=agent,
            steps=agent_events,
            categories_seen=cats,
            violation_score=round(score, 1),
        ))
    chains.sort(key=lambda c: c.violation_score, reverse=True)
    return chains


def analyze_phishing(events: list[dict[str, Any]]) -> PhishingReport:
    all_violations: list[PhishingEvent] = []
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

    return PhishingReport(
        total_events=len(events),
        violation_events=len(all_violations),
        categories=categories,
        chains=chains,
        agents_involved=agents,
        severity_counts=dict(sev_counts),
    )


def format_text(report: PhishingReport) -> str:
    lines = [
        "Phishing Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:  {report.total_events}",
        f"  Phishing detections:    {report.violation_events}",
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


def format_json(report: PhishingReport) -> str:
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
