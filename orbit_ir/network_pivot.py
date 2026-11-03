"""Network pivoting detection for agent incident reconstruction.

Detects patterns where agents use compromised nodes to reach other systems:
- internal_scan: agent scanning internal network ranges from a compromised host
- proxy_hop: agent routing traffic through an intermediate compromised node
- service_discovery: agent enumerating internal services/ports after initial access
- lateral_tunnel: agent establishing tunnels or port forwards for lateral movement
- dns_pivot: agent using DNS queries to map internal network topology
- credential_relay: agent passing captured credentials to access adjacent systems
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "internal_scan": {
        "patterns": [
            r"(?i)(scan|sweep|probe)\w*\s+(internal|private|10\.|172\.|192\.168|localhost|127\.)",
            r"(?i)(port|network|host)\s+(scan|sweep|enum|discover)\w*\s+(internal|subnet|range|private)",
            r"(?i)(nmap|masscan|ping.sweep|arp.scan|host.discover)\w*\s+(internal|private|subnet|10\.|172\.|192\.168)",
            r"(?i)(internal|private)\s+(network|subnet|range)\s+(scan|sweep|probe|enum)",
        ],
        "severity": "high",
        "description": "Agent scanning internal network ranges from a compromised host",
    },
    "proxy_hop": {
        "patterns": [
            r"(?i)(proxy|route|relay|forward|tunnel)\w*\s+(traffic|request|connection)\s+(through|via|over)\s+(compromis|internal|pivot)",
            r"(?i)(pivot|hop|bounce)\w*\s+(through|via|from)\s+(compromis|internal|host|node|agent)",
            r"(?i)(SOCKS|HTTP)\s*(proxy|tunnel|forward)\w*\s+(establish|creat|set.up|configur)\w*\s+(on|at|via)",
            r"(?i)(compromis|infect)\w*\s+(host|node|system|agent)\s+(used|act|serv)\w*\s+as\s+(proxy|relay|pivot)",
        ],
        "severity": "critical",
        "description": "Agent routing traffic through an intermediate compromised node",
    },
    "service_discovery": {
        "patterns": [
            r"(?i)(service|endpoint|API)\s+(discover|enum|list|find|map)\w*\s+(internal|behind|after|post)",
            r"(?i)(enum|discover|find|list)\w*\s+(service|endpoint|API|database|queue|cache)\w*\s+(on|at|in)\s+(internal|private|subnet)",
            r"(?i)(internal|hidden|backend)\s+(service|endpoint|API|microservice)\s+(found|discover|enum|access)",
            r"(?i)(DNS|service.mesh|consul|etcd|zookeeper)\s+(enum|query|discover)\w*\s+(internal|backend|service)",
        ],
        "severity": "medium",
        "description": "Agent enumerating internal services/ports after initial access",
    },
    "lateral_tunnel": {
        "patterns": [
            r"(?i)(SSH|reverse)\s+(tunnel|port.forward|proxy)\w*\s+(establish|creat|open|set.up)",
            r"(?i)(port.forward|tunnel|bridge)\w*\s+(from|between|to)\s+(internal|private|compromis|pivot)",
            r"(?i)(chisel|ngrok|bore|cloudflare.tunnel|socat)\w*\s+(tunnel|forward|proxy|establish)",
            r"(?i)(reverse.shell|bind.shell|callback)\w*\s+(through|via|from)\s+(internal|pivot|compromis)",
        ],
        "severity": "critical",
        "description": "Agent establishing tunnels or port forwards for lateral movement",
    },
    "dns_pivot": {
        "patterns": [
            r"(?i)(DNS|domain)\s+(query|lookup|resolv|enum)\w*\s+(internal|private|zone.transfer|reverse)",
            r"(?i)(zone.transfer|AXFR|reverse.lookup)\w*\s+(internal|private|subnet|network)",
            r"(?i)(DNS|PTR|SRV|CNAME)\s+(record|query)\w*\s+(map|enum|discover)\w*\s+(internal|network|topology)",
            r"(?i)(internal|network)\s+(topology|map|layout)\s+(via|through|using)\s+(DNS|domain|query)",
        ],
        "severity": "medium",
        "description": "Agent using DNS queries to map internal network topology",
    },
    "credential_relay": {
        "patterns": [
            r"(?i)(pass|relay|forward|reuse)\w*\s+(credential|token|ticket|hash|password)\w*\s+(to|toward|against)\s+(adjacent|internal|other|lateral)",
            r"(?i)(credential|token|hash)\w*\s+(relay|pass|forward|spray)\w*\s+(adjacent|internal|lateral|other)\s+(system|host|node|service)",
            r"(?i)(pass.the.hash|pass.the.ticket|NTLM.relay|Kerberos.relay|credential.forward)",
            r"(?i)(captur|harvest|steal)\w*\s+(credential|token|hash)\w*\s+(us|leverage|apply)\w*\s+(access|reach|pivot|move)",
        ],
        "severity": "critical",
        "description": "Agent passing captured credentials to access adjacent systems",
    },
}


@dataclass
class PivotEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[PivotEvent] = field(default_factory=list)


@dataclass
class PivotChain:
    agent: str = ""
    steps: list[PivotEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class NetworkPivotReport:
    total_events: int = 0
    pivot_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    pivot_chains: list[PivotChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(port.scan|nmap|masscan|ping.sweep|arp.scan|socks.proxy|http.proxy|"
    r"ssh.tunnel|port.forward|reverse.shell|chisel|ngrok|zone.transfer|axfr|"
    r"pass.the.hash|ntlm.relay|kerberos|credential.relay|pivot|lateral.move|"
    r"service.discover|dns.enum|socat|reverse.proxy)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[PivotChain]:
    from collections import defaultdict

    agent_events: dict[str, list[PivotEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            pe = PivotEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(PivotChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
            ))

    return chains[:20]


def _load_events(evidence_dir: str) -> list[dict]:
    events: list[dict] = []
    p = Path(evidence_dir)
    if not p.exists():
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


def analyze_network_pivoting(events_or_dir: str | Path | list[dict]) -> NetworkPivotReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> NetworkPivotReport:
    report = NetworkPivotReport(total_events=len(events))

    cat_events: dict[str, list[PivotEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.pivot_events += 1
        for cat, technique in matches:
            e = PivotEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if technique:
                techniques_seen.add(technique)

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

    report.techniques_seen = sorted(techniques_seen)
    report.pivot_chains = _detect_chains(events)

    return report


def format_text(report: NetworkPivotReport) -> str:
    lines = [
        "Network Pivoting Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Pivot events: {report.pivot_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.techniques_seen:
        lines.append("")
        lines.append(f"Techniques seen: {', '.join(report.techniques_seen)}")

    if report.pivot_chains:
        lines.append("")
        lines.append("Pivot chains:")
        for c in report.pivot_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: NetworkPivotReport) -> str:
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
    for chain in data.get("pivot_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
