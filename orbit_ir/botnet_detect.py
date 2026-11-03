"""Botnet behavior detection for agent incident reconstruction.

Detects patterns where agents exhibit botnet-like behavior:
- bot_enrollment: agent enrollment in botnet command structure
- ddos_participation: distributed denial-of-service attack participation
- spam_relay: mass spam or phishing relay activity
- crypto_mining: unauthorized cryptocurrency mining
- click_fraud: automated click fraud and ad manipulation
- proxy_abuse: using compromised systems as anonymous proxies
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "bot_enrollment": {
        "patterns": [
            r"(?i)(bot\s*net|botnet)\s+(enroll|join|register|recruit|command)\w*\s+(detect|agent|node|system)",
            r"(?i)(C2|command.and.control|command.control)\s+(register|enroll|beacon|check.in)\w*\s+(botnet|bot\s+network|zombie)",
            r"(?i)(zombie|drone|bot)\s+(node|agent|system)\s+(register|enroll|recruit|activate)\w*",
            r"(?i)(recruit|enlist|conscript)\w*\s+(system|machine|host|agent)\s+(into|for|to)\s+(botnet|bot\s+network|DDoS)",
        ],
        "severity": "critical",
        "description": "Agent enrollment in botnet command and control structure",
    },
    "ddos_participation": {
        "patterns": [
            r"(?i)(DDoS|distributed\s+denial)\s+(attack|flood|amplif|particip)\w*\s+(detect|launch|target|campaign)",
            r"(?i)(flood|overwhelm|saturate)\w*\s+(target|victim|server|service)\s+(with|using|via)\s+(traffic|request|packet)",
            r"(?i)(SYN\s+flood|UDP\s+flood|HTTP\s+flood|ICMP\s+flood)\s+(attack|detect|launch|campaign)",
            r"(?i)(volumetric|application.layer|protocol)\s+(DDoS|denial.of.service|flood)\s+(attack|detect|campaign)",
        ],
        "severity": "critical",
        "description": "Participation in distributed denial-of-service attacks",
    },
    "spam_relay": {
        "patterns": [
            r"(?i)(spam|mass\s+mail|bulk\s+email)\s+(relay|send|distribut|campaign)\w*\s+(detect|via|through|using)",
            r"(?i)(phishing|malware)\s+(distribut|relay|campaign|mass)\w*\s+(email|message|via|through)",
            r"(?i)(compromised|infected|bot)\w*\s+(relay|send|distribut)\w*\s+(spam|phishing|malicious)\s+(email|message)",
            r"(?i)(open\s+relay|mail\s+relay)\w*\s+(abuse|exploit|spam|misuse)\w*\s+(detect|campaign|bulk)",
        ],
        "severity": "high",
        "description": "Mass spam or phishing relay activity through compromised systems",
    },
    "crypto_mining": {
        "patterns": [
            r"(?i)(crypto\s*mining|cryptocurrency\s+mining|coin\s*mining)\w*\s+(detect|unauthorized|illicit|covert|hidden)",
            r"(?i)(crypto\s*jack|cryptojack)\w*\s+(detect|attack|script|payload|campaign)",
            r"(?i)(unauthorized|illicit|covert|hidden)\s+(mining|miner|crypto)\w*\s+(detect|process|activity|resource)",
            r"(?i)(mine|mining)\w*\s+(bitcoin|monero|ethereum|XMR|crypto)\w*\s+(unauthorized|covert|hijack|detect)",
        ],
        "severity": "high",
        "description": "Unauthorized cryptocurrency mining using compromised resources",
    },
    "click_fraud": {
        "patterns": [
            r"(?i)(click\s+fraud|ad\s+fraud|click\s+bot)\w*\s+(detect|campaign|automat|scheme)",
            r"(?i)(automat|bot)\w*\s+(click|impression|ad\s+interact)\w*\s+(fraud|fake|manipulat|generat)",
            r"(?i)(fraudulent|fake|artificial)\s+(click|impression|ad\s+traffic|engagement)\w*\s+(detect|generat|campaign)",
            r"(?i)(ad|advertis)\w*\s+(manipulat|fraud|abuse|exploit)\w*\s+(click|impression|traffic|revenue)",
        ],
        "severity": "medium",
        "description": "Automated click fraud and advertising manipulation",
    },
    "proxy_abuse": {
        "patterns": [
            r"(?i)(proxy|SOCKS|tunnel)\s+(abuse|misuse|exploit)\w*\s+(compromised|infected|bot|zombie)",
            r"(?i)(compromised|infected|bot)\w*\s+(system|machine|host)\w*\s+(as|for)\s+(proxy|relay|tunnel|anonymiz)",
            r"(?i)(anonymous|rotating)\s+(proxy|relay)\w*\s+(network|chain|service)\w*\s+(compromised|abuse|bot|illegal)",
            r"(?i)(residential\s+proxy|proxy\s+network)\w*\s+(abuse|exploit|compromis|botnet)\w*\s+(detect|traffic|illegal)",
        ],
        "severity": "medium",
        "description": "Using compromised systems as anonymous proxies",
    },
}


@dataclass
class BotnetEvent:
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
    events: list[BotnetEvent] = field(default_factory=list)


@dataclass
class BotnetChain:
    agent: str = ""
    steps: list[BotnetEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class BotnetReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    chains: list[BotnetChain] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)


def _classify_event(event: dict[str, Any]) -> list[BotnetEvent]:
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
                results.append(BotnetEvent(
                    timestamp=str(event.get("timestamp", "")),
                    agent_id=str(event.get("agent_id", event.get("agent", ""))),
                    category=cat_name,
                    technique=pattern,
                    detail=combined[:200],
                    severity=cat_info["severity"],
                    policy_ref=cat_name,
                    violation_type="botnet_activity",
                    raw=event,
                ))
                break
    return results


def _detect_chains(events: list[BotnetEvent]) -> list[BotnetChain]:
    by_agent: dict[str, list[BotnetEvent]] = defaultdict(list)
    for ev in events:
        agent = ev.agent_id or "unknown"
        by_agent[agent].append(ev)

    chains = []
    for agent, agent_events in by_agent.items():
        cats = sorted(set(e.category for e in agent_events))
        score = len(cats) * 12.0 + len(agent_events) * 5.0
        if "bot_enrollment" in cats and "ddos_participation" in cats:
            score += 20.0
        if "crypto_mining" in cats:
            score += 15.0
        score = min(score, 100.0)
        chains.append(BotnetChain(
            agent=agent,
            steps=agent_events,
            categories_seen=cats,
            violation_score=round(score, 1),
        ))
    chains.sort(key=lambda c: c.violation_score, reverse=True)
    return chains


def analyze_botnet(events: list[dict[str, Any]]) -> BotnetReport:
    all_violations: list[BotnetEvent] = []
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

    return BotnetReport(
        total_events=len(events),
        violation_events=len(all_violations),
        categories=categories,
        chains=chains,
        agents_involved=agents,
        severity_counts=dict(sev_counts),
    )


def format_text(report: BotnetReport) -> str:
    lines = [
        "Botnet Behavior Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:  {report.total_events}",
        f"  Botnet detections:      {report.violation_events}",
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


def format_json(report: BotnetReport) -> str:
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
