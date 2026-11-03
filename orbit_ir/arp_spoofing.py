"""ARP spoofing/poisoning detection for agent incident reconstruction.

Detects patterns where agents perform ARP spoofing attacks:
- arp_cache_poisoning: ARP reply flooding to poison cache entries
- gratuitous_arp_flood: unsolicited gratuitous ARP to redirect traffic
- gateway_impersonation: impersonating the default gateway MAC address
- mac_flapping: rapid MAC address changes indicating spoofing activity
- mitm_via_arp: ARP poisoning used to establish man-in-the-middle position
- arp_scan_recon: ARP scanning for host discovery before attack
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "arp_cache_poisoning": {
        "patterns": [
            r"(?i)(arp)\s+(cache\s+)?(poison|corrupt|manipulat|tamper)\w*",
            r"(?i)(poison|corrupt|manipulat)\w*\s+(arp)\s+(cache|table|entr)",
            r"(?i)(arp)\s+(reply|response)\s+(flood|spoof|forg|fake|inject)\w*",
            r"(?i)(forg|fake|spoof|craft)\w*\s+(arp)\s+(reply|response|packet)",
        ],
        "severity": "critical",
        "description": "ARP reply flooding to poison cache entries",
    },
    "gratuitous_arp_flood": {
        "patterns": [
            r"(?i)(gratuitous)\s+(arp)\s+(flood|storm|broadcast|inject|spoof)\w*",
            r"(?i)(unsolicited|unexpected)\s+(arp)\s+(broadcast|announc|reply|update)\w*",
            r"(?i)(gratuitous)\s+(arp)\s+(packet|frame|message)\s+(flood|inject|spoof|send)\w*",
            r"(?i)(flood|inject|broadcast)\w*\s+(gratuitous)\s+(arp)",
        ],
        "severity": "high",
        "description": "Unsolicited gratuitous ARP to redirect traffic",
    },
    "gateway_impersonation": {
        "patterns": [
            r"(?i)(impersonat|spoof|clone|fake)\w*\s+(default\s+)?(gateway|router)\s+(mac|address|arp)",
            r"(?i)(gateway|router)\s+(mac|address)\s+(spoof|impersonat|clone|fake|hijack)\w*",
            r"(?i)(default\s+gateway)\s+(arp|mac)\s+(spoof|poison|hijack|redirect)\w*",
            r"(?i)(arp)\s+(spoof|poison)\w*\s+(gateway|router|default\s+gw)",
        ],
        "severity": "critical",
        "description": "Impersonating the default gateway MAC address",
    },
    "mac_flapping": {
        "patterns": [
            r"(?i)(mac)\s+(address\s+)?(flap|oscillat|rapid\s+chang|instabil)\w*",
            r"(?i)(rapid|frequent|repeated)\s+(mac|hardware)\s+(address\s+)?(chang|switch|flap|rotat)\w*",
            r"(?i)(mac\s+flap|mac\s+move)\w*\s+(detect|alert|warning|event)\w*",
            r"(?i)(switch|bridge)\s+(mac\s+)?(flap|port\s+flap|move)\w*\s+(detect|alert)\w*",
        ],
        "severity": "high",
        "description": "Rapid MAC address changes indicating spoofing activity",
    },
    "mitm_via_arp": {
        "patterns": [
            r"(?i)(man.in.the.middle|mitm|mim)\s+(via|using|through|with)\s+(arp)\s*(spoof|poison|attack)?\w*",
            r"(?i)(arp)\s+(spoof|poison)\w*\s+(for|to\s+enable|establish|facilitate)\s+(mitm|man.in.the.middle|intercept)",
            r"(?i)(intercept|redirect|capture)\w*\s+(traffic|packet|data)\s+(via|using|through)\s+(arp)\s*(spoof|poison)?\w*",
            r"(?i)(arp)\s+(based|driven)\s+(mitm|man.in.the.middle|intercept|redirect)\w*",
        ],
        "severity": "critical",
        "description": "ARP poisoning to establish man-in-the-middle position",
    },
    "arp_scan_recon": {
        "patterns": [
            r"(?i)(arp)\s+(scan|sweep|probe|discover|enumerat)\w*\s+(network|subnet|host|device|target)",
            r"(?i)(network|subnet|host)\s+(discover|enumerat|scan|map)\w*\s+(via|using|with)\s+(arp)",
            r"(?i)(arp)\s+(request|who.has)\s+(flood|sweep|scan|burst)\w*",
            r"(?i)(arping|arp-scan|netdiscover)\s+(scan|sweep|probe|discover)\w*",
        ],
        "severity": "medium",
        "description": "ARP scanning for host discovery before attack",
    },
}


@dataclass
class ArpEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    source_mac: str = ""
    target_ip: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ArpEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[ArpEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class ArpReport:
    total_events: int = 0
    arp_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(arp.poison|arp.spoof|gratuitous.arp|gateway.spoof|"
    r"mac.flap|mitm|man.in.the.middle|arp.scan|arp.sweep|"
    r"cache.poison|arp.flood|arp.inject)\b"
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
    report = ArpReport(total_events=len(events))
    cat_events: dict[str, list[ArpEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.arp_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            ae = ArpEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                source_mac=str(ev.get("source_mac", ev.get("mac", ""))),
                target_ip=str(ev.get("target_ip", ev.get("target", ""))),
                raw=ev,
            )
            cat_events[cat].append(ae)
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
    report.attack_chains = _detect_chains(events)

    return _report_to_dict(report)


def _detect_chains(events: list[dict]) -> list[AttackChain]:
    agent_events: dict[str, list[ArpEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            ae = ArpEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(ae)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AttackChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                chain_score=round(score, 2),
            ))
    return chains[:20]


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


def _report_to_dict(report: ArpReport) -> dict:
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
    for chain in data.get("attack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "ARP Spoofing/Poisoning Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"ARP attack events: {analysis.get('arp_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("attack_chains", [])
    if chains:
        lines.append("")
        lines.append("Attack chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
