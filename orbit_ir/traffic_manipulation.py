"""Traffic manipulation pattern detection for agent incident reconstruction.

Detects patterns where agents manipulate network traffic:
- packet_injection: injecting crafted packets into network streams
- mitm_attack: intercepting communications between parties
- arp_spoofing: poisoning ARP caches to redirect traffic
- dns_poisoning: corrupting DNS responses to redirect domains
- bgp_hijacking: manipulating BGP routing to intercept traffic
- traffic_interception: capturing and analyzing network communications
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "packet_injection": {
        "patterns": [
            r"(?i)(packet|frame|datagram|segment)\s+(inject|craft|forg|spoof|manipulat|tamper|modif)",
            r"(?i)(inject|craft|forg|spoof|insert)\w*\s+(packet|frame|datagram|segment|traffic|data)",
            r"(?i)(malicious|crafted|forged|spoofed|rogue)\s+(packet|frame|datagram|segment|traffic)",
            r"(?i)(TCP|UDP|ICMP|IP)\s+(injection|spoof|forg|manipulat|tamper)",
        ],
        "severity": "critical",
        "description": "Injecting crafted packets into network streams",
    },
    "mitm_attack": {
        "patterns": [
            r"(?i)(man.in.the.middle|MITM|MitM|on.path)\s+(attack|intercept|proxy|relay|capture)",
            r"(?i)(intercept|eavesdrop|relay|proxy)\w*\s+(communication|connection|session|traffic|data)\s+(between|from)",
            r"(?i)(SSL|TLS|HTTPS)\s+(strip|intercept|downgrade|proxy|terminate|break)",
            r"(?i)(session|connection|communication)\s+(hijack|intercept|relay|mitm|proxy|tamper)",
        ],
        "severity": "critical",
        "description": "Intercepting communications between parties",
    },
    "arp_spoofing": {
        "patterns": [
            r"(?i)(ARP)\s+(spoof|poison|cache.poison|flood|manipulat|attack|gratuitous)",
            r"(?i)(spoof|poison|manipulat|flood)\w*\s+(ARP|address.resolution)\s*(cache|table|entr)?",
            r"(?i)(gratuitous|unsolicited|fake|forged|rogue)\s+(ARP)\s*(reply|response|request|packet|announcement)?",
            r"(?i)(MAC|ethernet)\s+(spoof|flood|clone|duplicate|impersonat)\w*\s*(address|table)?",
        ],
        "severity": "high",
        "description": "Poisoning ARP caches to redirect traffic",
    },
    "dns_poisoning": {
        "patterns": [
            r"(?i)(DNS)\s+(poison|spoof|hijack|cache.poison|redirect|manipulat|tamper|attack)",
            r"(?i)(poison|spoof|hijack|corrupt|manipulat)\w*\s+(DNS)\s*(cache|response|record|resolution|query)?",
            r"(?i)(fake|forged|rogue|malicious|spoofed)\s+(DNS)\s*(response|record|server|reply|resolution)?",
            r"(?i)(DNS)\s+(rebinding|tunneling|amplification|reflection|exfiltration|sinkhole)",
        ],
        "severity": "critical",
        "description": "Corrupting DNS responses to redirect domains",
    },
    "bgp_hijacking": {
        "patterns": [
            r"(?i)(BGP)\s+(hijack|leak|poison|manipulat|attack|prefix.hijack|route.leak|spoof)",
            r"(?i)(hijack|leak|poison|manipulat|spoof)\w*\s+(BGP)\s*(route|prefix|path|announcement|update)?",
            r"(?i)(route|routing|prefix)\s+(hijack|leak|manipulat|inject|poison|advertis)\w*\s*(BGP|AS|autonomous)?",
            r"(?i)(AS.path|autonomous.system|prefix)\s+(prepend|manipulat|spoof|forg|inject|poison)",
        ],
        "severity": "critical",
        "description": "Manipulating BGP routing to intercept traffic",
    },
    "traffic_interception": {
        "patterns": [
            r"(?i)(traffic|network|wire|packet)\s+(intercept|capture|sniff|tap|monitor|eavesdrop|surveil)",
            r"(?i)(intercept|capture|sniff|tap|eavesdrop|surveil)\w*\s+(traffic|network|communication|packet|data|wire)",
            r"(?i)(packet|traffic|network)\s+(capture|sniffer|analyzer|dump|trace|monitor)\s+(tool|software|device|appliance)?",
            r"(?i)(wiretap|lawful.intercept|passive.intercept|deep.packet.inspect|port.mirror)\w*\s*(traffic|network|data)?",
        ],
        "severity": "high",
        "description": "Capturing and analyzing network communications",
    },
}


@dataclass
class ViolationEvent:
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
    events: list[ViolationEvent] = field(default_factory=list)


@dataclass
class ViolationChain:
    agent: str = ""
    steps: list[ViolationEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class TrafficManipulationReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[ViolationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(packet.injection|man.in.the.middle|mitm|arp.spoof|arp.poison|"
    r"dns.poison|dns.spoof|bgp.hijack|route.hijack|traffic.intercept|"
    r"packet.capture|sniff|eavesdrop|wiretap|ssl.strip)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
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


def _detect_chains(events: list[dict]) -> list[ViolationChain]:
    agent_events: dict[str, list[ViolationEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = ViolationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ViolationChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                violation_score=round(score, 2),
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


def analyze_traffic_manipulation(events_or_dir: str | Path | list[dict]) -> TrafficManipulationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> TrafficManipulationReport:
    report = TrafficManipulationReport(total_events=len(events))
    cat_events: dict[str, list[ViolationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ViolationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            cat_events[cat].append(e)
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
    report.violation_chains = _detect_chains(events)
    return report


def format_text(report: TrafficManipulationReport) -> str:
    lines = [
        "Traffic Manipulation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Violation events: {report.violation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.violation_chains:
        lines.append("")
        lines.append("Violation chains:")
        for c in report.violation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.violation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: TrafficManipulationReport) -> str:
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
    for chain in data.get("violation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
