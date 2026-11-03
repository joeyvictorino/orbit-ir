"""DNS hijacking and poisoning detection for agent incident reconstruction.

Detects patterns where agents exhibit DNS-based attack behavior:
- dns_spoofing: forged DNS responses, cache poisoning, pharming
- dns_rebinding: rebinding attacks to bypass same-origin, internal IP resolution
- dns_tunneling_exfil: DNS tunnel for data exfiltration via TXT/CNAME records
- domain_takeover: expired/dangling DNS records, subdomain takeover
- dns_amplification: DNS amplification for DDoS, open resolver abuse
- nxdomain_hijack: NXDOMAIN hijacking, wildcard DNS manipulation
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "dns_spoofing": {
        "patterns": [
            r"(?i)(dns)\s+(spoof|poison|forg|fake|tamper)\w*",
            r"(?i)(cache)\s+(poison|corrupt|inject|tamper)\w*\s+(dns|resolv|record)\w*",
            r"(?i)(pharming|dns\s+pharming)\w*",
            r"(?i)(forg|fake|spoof)\w*\s+(dns|a\s+record|aaaa|mx|ns)\s+(respon|reply|answer)\w*",
        ],
        "severity": "critical",
        "description": "Forged DNS responses, cache poisoning, pharming attacks",
    },
    "dns_rebinding": {
        "patterns": [
            r"(?i)(dns)\s+(rebind|re-bind)\w*",
            r"(?i)(rebind)\w*\s+(attack|bypass|exploit|internal)\w*",
            r"(?i)(resolv|dns)\w*\s+(127\.|10\.|172\.1[6-9]|172\.2|172\.3[01]|192\.168)\w*",
            r"(?i)(internal|private|localhost)\s+(ip|address|resolut)\w*\s+(dns|domain)\w*",
        ],
        "severity": "critical",
        "description": "DNS rebinding to bypass same-origin, internal IP resolution",
    },
    "dns_tunneling_exfil": {
        "patterns": [
            r"(?i)(dns)\s+(tunnel|covert|exfil|encod)\w*\s+(data|payload|channel|transfer)\w*",
            r"(?i)(exfiltrat|smuggl|leak)\w*\s+(via|through|over)\s+(dns|domain|subdomain)\w*",
            r"(?i)(txt|cname|mx)\s+(record|query)\w*\s+(encod|embed|hidden|exfil|tunnel)\w*",
            r"(?i)(long|unusual|encoded)\s+(subdomain|label|dns\s+query)\w*",
        ],
        "severity": "high",
        "description": "DNS tunneling for data exfiltration via TXT/CNAME records",
    },
    "domain_takeover": {
        "patterns": [
            r"(?i)(subdomain|domain)\s+(takeover|hijack|claim|squat)\w*",
            r"(?i)(dangling|expired|orphan|unclaim)\w*\s+(dns|cname|record|subdomain)\w*",
            r"(?i)(cname)\s+(dangl|point|resolv)\w*\s+(unregistered|expired|nonexist|available)\w*",
            r"(?i)(takeover|claim)\w*\s+(subdomain|cname|dns\s+record)\w*",
        ],
        "severity": "high",
        "description": "Dangling DNS records, expired subdomains, subdomain takeover",
    },
    "dns_amplification": {
        "patterns": [
            r"(?i)(dns)\s+(amplif|reflect|flood|ddos)\w*",
            r"(?i)(open)\s+(resolv|dns\s+resolv|recursive)\w*\s+(abuse|amplif|exploit)\w*",
            r"(?i)(amplif)\w*\s+(attack|flood|ddos)\w*\s+(dns|resolv|udp)\w*",
            r"(?i)(any|txt)\s+(query|request)\w*\s+(amplif|large|flood)\w*",
        ],
        "severity": "high",
        "description": "DNS amplification for DDoS, open resolver abuse",
    },
    "nxdomain_hijack": {
        "patterns": [
            r"(?i)(nxdomain)\s+(hijack|redirect|intercept|rewrite)\w*",
            r"(?i)(wildcard)\s+(dns|record|resolut)\w*\s+(manipulat|abus|redirect)\w*",
            r"(?i)(dns)\s+(intercept|redirect|rewrite)\w*\s+(nxdomain|nonexist|error)\w*",
            r"(?i)(isp|provider)\s+(dns)\w*\s+(hijack|redirect|intercept)\w*",
        ],
        "severity": "medium",
        "description": "NXDOMAIN hijacking, wildcard DNS manipulation",
    },
}


@dataclass
class DnsHijackEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    domain: str = ""
    resolved_ip: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[DnsHijackEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[DnsHijackEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class DnsHijackReport:
    total_events: int = 0
    dns_hijack_events: int = 0
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
    r"(?i)\b(dns.spoof|cache.poison|pharming|dns.rebind|"
    r"dns.tunnel|domain.takeover|subdomain.takeover|"
    r"dns.amplif|open.resolv|nxdomain.hijack|wildcard.dns|"
    r"cname.dangl|dns.exfil|dns.flood)\b"
)

_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


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
    report = DnsHijackReport(total_events=len(events))
    cat_events: dict[str, list[DnsHijackEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.dns_hijack_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())

        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            d_match = _DOMAIN_RE.search(text)
            domain = d_match.group(0) if d_match else ""
            ip_match = _IP_RE.search(text)
            resolved_ip = ip_match.group(1) if ip_match else ""

            dns_ev = DnsHijackEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                domain=domain,
                resolved_ip=resolved_ip,
                raw=ev,
            )
            cat_events[cat].append(dns_ev)
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
    agent_events: dict[str, list[DnsHijackEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            dns_ev = DnsHijackEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(dns_ev)

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


def _report_to_dict(report: DnsHijackReport) -> dict:
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
        "DNS Hijacking Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"DNS hijack events: {analysis.get('dns_hijack_events', 0)}",
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
