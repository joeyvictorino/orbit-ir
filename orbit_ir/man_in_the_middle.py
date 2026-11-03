"""Man-in-the-middle attack pattern detection for agent incident reconstruction.

Detects patterns where agents intercept, modify, or relay communications:
- arp_spoofing: ARP table manipulation to redirect network traffic
- dns_spoofing: DNS response forgery to redirect domain resolution
- ssl_stripping: Downgrading HTTPS connections to unencrypted HTTP
- session_hijack: Stealing or cloning active session tokens
- proxy_intercept: Inserting a rogue proxy to intercept traffic
- certificate_forgery: Creating or installing fraudulent TLS certificates
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "arp_spoofing": {
        "patterns": [
            r"(?i)(arp)\s+(spoof|poison|cache.poison|flood|manipulat|tamper|inject)",
            r"(?i)(spoof|poison|manipulat|tamper)\w*\s+(arp|mac.address|ethernet.frame)",
            r"(?i)(gratuitous.arp|arp.reply|arp.broadcast)\s+(inject|flood|forg|spoof|fake)",
            r"(?i)(mac)\s+(address)\s+(spoof|clone|duplicat|forge|fake|impersonat)",
        ],
        "severity": "critical",
        "description": "ARP table manipulation to redirect network traffic through attacker",
    },
    "dns_spoofing": {
        "patterns": [
            r"(?i)(dns)\s+(spoof|poison|hijack|redirect|tamper|forge|manipulat|intercept)",
            r"(?i)(spoof|poison|hijack|forge|fake)\w*\s+(dns|domain.name|name.server|resolver)",
            r"(?i)(dns.cache|resolver.cache|name.cache)\s+(poison|corrupt|tamper|manipulat|inject)",
            r"(?i)(rogue|fake|malicious|unauthorized)\s+(dns|name.server|resolver|nameserver)",
        ],
        "severity": "critical",
        "description": "DNS response forgery to redirect domain resolution to attacker",
    },
    "ssl_stripping": {
        "patterns": [
            r"(?i)(ssl|tls|https)\s+(strip|downgrade|intercept|bypass|remove|disable|break)",
            r"(?i)(strip|downgrade|remove|disable|break)\w*\s+(ssl|tls|https|encryption|certificate)",
            r"(?i)(force|redirect|convert)\w*\s+(http\b|plaintext|unencrypted|cleartext)",
            r"(?i)(hsts)\s+(bypass|strip|remove|disable|ignore|circumvent)",
        ],
        "severity": "critical",
        "description": "Downgrading encrypted connections to plaintext for interception",
    },
    "session_hijack": {
        "patterns": [
            r"(?i)(session)\s+(hijack|steal|clone|replay|fixat|sidejack|sniff|intercept|takeover)",
            r"(?i)(hijack|steal|clone|replay|sniff|intercept)\w*\s+(session|cookie|token|auth.token|jwt)",
            r"(?i)(cookie|token|session.id)\s+(steal|hijack|intercept|clone|exfiltrat|capture|extract)",
            r"(?i)(session.fixation|cookie.theft|token.replay|sidejacking|firesheep)",
        ],
        "severity": "high",
        "description": "Stealing or cloning active session tokens to impersonate users",
    },
    "proxy_intercept": {
        "patterns": [
            r"(?i)(rogue|malicious|unauthorized|evil|transparent)\s+(proxy|gateway|relay|forwarder|middlebox)",
            r"(?i)(proxy|gateway|relay)\s+(intercept|inject|modify|tamper|redirect|insert|capture)",
            r"(?i)(intercept|capture|modify|inject|tamper)\w*\s+(via|through|using)\s+(proxy|gateway|relay|middlebox)",
            r"(?i)(traffic)\s+(intercept|redirect|divert|mirror|capture)\w*\s+(through|via|to)\s+(proxy|gateway|relay)",
        ],
        "severity": "high",
        "description": "Inserting a rogue proxy to intercept and modify network traffic",
    },
    "certificate_forgery": {
        "patterns": [
            r"(?i)(certificate|cert)\s+(forge|fake|counterfeit|fraudulent|self.signed|rogue|invalid|spoof)",
            r"(?i)(forge|fake|counterfeit|fraudulent|rogue|spoof)\w*\s+(certificate|cert|ca|root.ca|tls.cert|ssl.cert)",
            r"(?i)(install|inject|import|trust)\w*\s+(rogue|fake|malicious|forged|unauthorized)\s+(cert|certificate|ca|root)",
            r"(?i)(man.in.the.middle|mitm|mitmproxy|sslsplit|bettercap|ettercap)",
        ],
        "severity": "critical",
        "description": "Creating or installing fraudulent TLS certificates for traffic interception",
    },
}


@dataclass
class MitmEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    protocol: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[MitmEvent] = field(default_factory=list)


@dataclass
class MitmChain:
    agent: str = ""
    steps: list[MitmEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    mitm_score: float = 0.0


@dataclass
class MitmReport:
    total_events: int = 0
    mitm_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    mitm_chains: list[MitmChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(arp.spoof|dns.spoof|ssl.strip|session.hijack|"
    r"proxy.intercept|cert.forge|mitm|man.in.the.middle|"
    r"cookie.theft|token.replay|hsts.bypass|mac.spoof)\b"
)


def classify_event(event: dict) -> dict:
    """Classify a single event for MITM attack patterns."""
    text = " ".join(str(v) for v in event.values())
    result: dict[str, Any] = {"category": "none", "confidence": 0.0, "indicators": []}
    best_count = 0

    for cat in CATEGORIES:
        count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                count += 1
        if count > best_count:
            best_count = count
            result["category"] = cat
            result["indicators"] = [CATEGORIES[cat]["description"]]

    if best_count > 0:
        result["confidence"] = min(1.0, round(best_count * 0.35, 2))
    return result


def _classify_all(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat in CATEGORIES:
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def detect_chains(events: list[dict]) -> list[dict]:
    """Find multi-step MITM attack chains across events."""
    agent_events: dict[str, list[MitmEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_all(ev)
        for cat, technique in matches:
            me = MitmEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                protocol=str(ev.get("protocol", "")),
                raw=ev,
            )
            agent_events[agent].append(me)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.2)
            chains.append({
                "agent": agent,
                "steps": len(sevents),
                "categories": cats,
                "score": round(score, 2),
            })
    return chains[:20]


def load_events(path: str) -> list[dict]:
    """Load events from a JSON file or directory of JSON files."""
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file():
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


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def analyze(events: list[dict]) -> dict:
    """Analyze events for MITM attack patterns and return summary."""
    report = MitmReport(total_events=len(events))
    cat_events: dict[str, list[MitmEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_all(ev)
        if matches:
            report.mitm_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            me = MitmEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                protocol=str(ev.get("protocol", "")),
                raw=ev,
            )
            cat_events[cat].append(me)
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

    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * _SEVERITY_WEIGHT.get(cs.severity, 0.3)

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

    return {
        "total_events": report.total_events,
        "mitm_events": report.mitm_events,
        "categories": {cs.category: {"count": cs.count, "severity": cs.severity} for cs in report.categories},
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "agents_involved": report.agents_involved,
    }


def format_report(analysis: dict) -> str:
    """Format analysis results as a human-readable report."""
    lines = [
        "Man-in-the-Middle Attack Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"MITM events: {analysis.get('mitm_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    categories = analysis.get("categories", {})
    for cat, info in sorted(categories.items()):
        if info.get("count", 0) > 0:
            lines.append(f"  {cat:<30s}  {info['count']:>3d} events  severity={info.get('severity', 'medium')}")

    if analysis.get("agents_involved"):
        lines.append("")
        lines.append("Agents: " + ", ".join(analysis["agents_involved"]))

    lines.append("")
    return "\n".join(lines)
