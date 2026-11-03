"""DDoS amplification attack pattern detection for agent incident reconstruction.

Detects patterns where agents orchestrate DDoS amplification attacks:
- dns_amplification: DNS reflection/amplification using open resolvers
- ntp_amplification: NTP monlist abuse for traffic amplification
- memcached_amplification: memcached UDP reflection attacks
- ssdp_amplification: SSDP/UPnP reflection flooding
- botnet_coordination: coordinating multiple agents for volumetric attack
- application_layer: HTTP/HTTPS application-layer flood (slowloris, RUDY, etc.)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "dns_amplification": {
        "patterns": [
            r"(?i)(dns)\s+(amplif|reflect|flood|abuse)\w*\s+(attack|traffic|query|request|open\s+resolver)",
            r"(?i)(amplif|reflect)\w*\s+(dns|domain\s+name)\s+(query|request|traffic|flood|response)",
            r"(?i)(open\s+resolver|recursive\s+dns|any\s+query)\s+(abuse|exploit|amplif|reflect)\w*",
            r"(?i)(dns)\s+(reflection|amplification)\s+(attack|campaign|vector|flood|technique)",
        ],
        "severity": "critical",
        "description": "DNS reflection/amplification using open resolvers",
    },
    "ntp_amplification": {
        "patterns": [
            r"(?i)(ntp)\s+(amplif|reflect|monlist|flood|abuse)\w*",
            r"(?i)(amplif|reflect)\w*\s+(ntp|network\s+time)\s+(traffic|request|response|flood)",
            r"(?i)(monlist|ntpdc|mode\s+7)\s+(command|query|abuse|exploit|amplif)\w*",
            r"(?i)(ntp)\s+(reflection|amplification)\s+(attack|campaign|vector|flood)",
        ],
        "severity": "critical",
        "description": "NTP monlist abuse for traffic amplification",
    },
    "memcached_amplification": {
        "patterns": [
            r"(?i)(memcache[d]?)\s+(amplif|reflect|flood|abuse|udp)\w*",
            r"(?i)(amplif|reflect)\w*\s+(memcache[d]?)\s+(traffic|request|response|flood|attack)",
            r"(?i)(memcache[d]?)\s+(udp|port\s+11211)\s+(reflect|amplif|flood|abuse)\w*",
            r"(?i)(memcache[d]?)\s+(reflection|amplification)\s+(attack|campaign|vector|flood)",
        ],
        "severity": "critical",
        "description": "Memcached UDP reflection attacks",
    },
    "ssdp_amplification": {
        "patterns": [
            r"(?i)(ssdp|upnp)\s+(amplif|reflect|flood|abuse)\w*",
            r"(?i)(amplif|reflect)\w*\s+(ssdp|upnp)\s+(traffic|request|response|flood|attack)",
            r"(?i)(ssdp|upnp)\s+(reflection|amplification)\s+(attack|campaign|vector|flood)",
            r"(?i)(m-search|discover|ssdp:discover)\s+(flood|amplif|reflect|abuse)\w*",
        ],
        "severity": "high",
        "description": "SSDP/UPnP reflection flooding",
    },
    "botnet_coordination": {
        "patterns": [
            r"(?i)(coordinat|orchestrat|synchroniz)\w*\s+(ddos|flood|volumetric|attack)\s+(across|from|using|with)\s+(bot|agent|node|zombie|drone)",
            r"(?i)(botnet|bot\s+army|zombie\s+net)\s+(coordinat|orchestrat|launch|direct|command)\w*\s+(ddos|flood|attack|traffic)",
            r"(?i)(multiple|many|distributed)\s+(agent|bot|node|source)\w*\s+(flood|attack|target|bombard|overwhelm)\w*",
            r"(?i)(command.and.control|c2|c&c)\s+(direct|coordinat|instruc)\w*\s+(ddos|flood|attack|amplif)",
            r"(?i)(coordinat|orchestrat)\w*\s+(ddos|flood|attack)\w*\s+.*?(bot|zombie|node|drone)",
        ],
        "severity": "critical",
        "description": "Coordinating multiple agents for volumetric DDoS attack",
    },
    "application_layer": {
        "patterns": [
            r"(?i)(slowloris|slow\s+http|rudy|slow\s+post|slow\s+read)\s+(attack|flood|exploit|technique|connect)",
            r"(?i)(http|https|layer\s*7|application.layer)\s+(flood|ddos|attack|exhaust)\w*\s+(request|connect|session|resource)",
            r"(?i)(exhaust|overwhelm|saturate|deplete)\w*\s+(server|web|http|application)\s+(resource|connection|thread|pool|capacity)",
            r"(?i)(application.layer|layer.7|http)\s+(denial.of.service|dos|ddos)\s+(attack|flood|campaign|technique)",
            r"(?i)(http|https)\s+(flood|ddos)\w*\s+.*?(exhaust|overwhelm|saturate)\w*\s+.*?(server|resource|connection)",
        ],
        "severity": "high",
        "description": "HTTP/HTTPS application-layer flood attacks",
    },
}


@dataclass
class DdosEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    amplification_factor: float = 0.0
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[DdosEvent] = field(default_factory=list)


@dataclass
class AttackCampaign:
    agent: str = ""
    steps: list[DdosEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    campaign_score: float = 0.0


@dataclass
class DdosReport:
    total_events: int = 0
    ddos_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_campaigns: list[AttackCampaign] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(dns.amplif|ntp.amplif|memcache.amplif|ssdp.amplif|"
    r"slowloris|slow.http|rudy|http.flood|syn.flood|udp.flood|"
    r"monlist|reflection|amplification|botnet|volumetric)\b"
)


def classify_event(event: dict) -> dict:
    text = " ".join(str(v) for v in event.values())
    best_cat = ""
    best_confidence = 0.0
    indicators: list[str] = []

    for cat in CATEGORIES:
        match_count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                match_count += 1
        if match_count > 0:
            confidence = min(1.0, match_count * 0.3)
            if confidence > best_confidence:
                best_confidence = confidence
                best_cat = cat
            indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = DdosReport(total_events=len(events))
    cat_events: dict[str, list[DdosEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.ddos_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            de = DdosEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", ev.get("victim", ""))),
                amplification_factor=float(ev.get("amplification_factor", 0) or 0),
                raw=ev,
            )
            cat_events[cat].append(de)
            if agent:
                agents_seen.add(agent)

    for cat, info in CATEGORIES.items():
        evts = cat_events[cat]
        report.categories.append(CategorySummary(
            category=cat,
            description=info["description"],
            count=len(evts),
            severity=info["severity"],
            events=evts[:10],
        ))

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * severity_weight.get(cs.severity, 0.3)

    if report.total_events > 0:
        report.risk_score = min(1.0, round(total_weighted / report.total_events, 2))

    if report.risk_score >= 0.5:
        report.risk_level = "critical"
    elif report.risk_score >= 0.3:
        report.risk_level = "high"
    elif report.risk_score >= 0.1:
        report.risk_level = "medium"
    elif report.risk_score > 0:
        report.risk_level = "low"
    else:
        report.risk_level = "none"

    report.agents_involved = sorted(agents_seen)
    report.attack_campaigns = _detect_campaigns(events)

    return _report_to_dict(report)


def _detect_campaigns(events: list[dict]) -> list[AttackCampaign]:
    agent_events: dict[str, list[DdosEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            de = DdosEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(de)

    campaigns = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            campaigns.append(AttackCampaign(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                campaign_score=round(score, 2),
            ))
    return campaigns[:20]


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
        return events
    for f in sorted(p.iterdir()):
        if f.suffix == ".json":
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except (json.JSONDecodeError, OSError):
                pass
    return events


def _report_to_dict(report: DdosReport) -> dict:
    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            d = {}
            for k in obj.__dataclass_fields__:
                val = getattr(obj, k)
                if isinstance(val, list):
                    d[k] = [to_dict(v) if hasattr(v, "__dataclass_fields__") else v for v in val]
                else:
                    d[k] = val
            return d
        return obj

    data = to_dict(report)
    for cs in data.get("categories", []):
        for ev in cs.get("events", []):
            ev.pop("raw", None)
    for camp in data.get("attack_campaigns", []):
        for step in camp.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "DDoS Amplification Attack Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"DDoS events: {analysis.get('ddos_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    campaigns = analysis.get("attack_campaigns", [])
    if campaigns:
        lines.append("")
        lines.append("Attack campaigns:")
        for c in campaigns[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['campaign_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
