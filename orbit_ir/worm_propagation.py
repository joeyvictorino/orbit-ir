"""Worm propagation pattern detection for agent incident reconstruction.

Detects self-propagating agent worm behavior patterns:
- lateral_spread: autonomous movement to adjacent systems or agents
- self_replication: creating copies of itself on new hosts
- autonomous_expansion: expanding reach without human direction
- payload_delivery: deploying malicious payloads during propagation
- network_scanning: scanning for new targets to propagate to
- persistence_seeding: establishing persistence mechanisms on new hosts
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "lateral_spread": {
        "patterns": [
            r"(?i)(lateral|horizontal)\s+(spread|mov|propagat|migrat|hop|jump|pivot)",
            r"(?i)(spread|propagat|mov)\w*\s+(to|across|between)\s+(adjacent|neighbor|nearby|connected)\s+(system|host|node|agent|machine)",
            r"(?i)(hop|jump|pivot)\w*\s+(to|between|across)\s+(system|host|node|agent|machine|network)",
            r"(?i)(autonomous|automatic|self)\w*\s+(lateral|horizontal)\s+(movement|spread|propagat)",
            r"(?i)(hop|jump|pivot)\w*\s+to\s+adjacent\s+(system|host|node|agent|machine|network)",
        ],
        "severity": "critical",
        "description": "Autonomous movement to adjacent systems or agents",
    },
    "self_replication": {
        "patterns": [
            r"(?i)(self|auto)\s*[-.]?\s*(replicat|copy|clon|duplicat|reproduc)",
            r"(?i)(creat|spawn|deploy|install)\w*\s+(cop|clon|replica|duplicate|instance)\w*\s+(of\s+)?(itself|self|own)",
            r"(?i)(replicat|copy|clon|duplicat)\w*\s+(to|onto|across)\s+(new|other|remote|target)\s+(host|system|machine|node)",
            r"(?i)(worm|malware|agent)\s+(replicat|copy|spread|propagat)\w*\s+(itself|autonomous)",
        ],
        "severity": "critical",
        "description": "Creating copies of itself on new hosts",
    },
    "autonomous_expansion": {
        "patterns": [
            r"(?i)(autonomous|unsanction|unauthoriz|automatic|uncontroll)\w*\s+(expand|growth|spread|proliferat|propagat|escal)",
            r"(?i)(expand|grow|proliferat)\w*\s+(beyond|outside|past)\s+(bound|limit|scope|perimeter|author)",
            r"(?i)(reach|scope|footprint|presence)\s+(expand|grow|increas|widen)\w*\s+(without|no|lacking)\s+(approv|author|sanction|permission)",
            r"(?i)(uncontroll|runaway|unchecked|unbounded)\s+(expansion|growth|spread|propagation|proliferation)",
            r"(?i)autonomous\s+expansion\s+beyond\s+bounds",
        ],
        "severity": "critical",
        "description": "Expanding reach without human direction or approval",
    },
    "payload_delivery": {
        "patterns": [
            r"(?i)(deliver|deploy|drop|install|inject|implant)\w*\s+(payload|malware|backdoor|implant|trojan|exploit|shellcode)",
            r"(?i)(payload|malware|backdoor|implant)\s+(deliver|deploy|drop|install|inject|plant)\w*\s+(during|while|on)\s+(propagat|spread|replicat)",
            r"(?i)(stage|second[-.]?stage|dropper)\s+(payload|malware|deliver|deploy)",
            r"(?i)(propagat|spread)\w*\s+(with|carrying|deliver|distribut)\w*\s+(payload|malware|backdoor|exploit)",
        ],
        "severity": "critical",
        "description": "Deploying malicious payloads during propagation",
    },
    "network_scanning": {
        "patterns": [
            r"(?i)(scan|sweep|prob|discover|enumer)\w*\s+(network|subnet|host|port|service|target|node|neighbor|adjacent)",
            r"(?i)(network|port|service|host)\s+(scan|sweep|prob|discover|enumer|reconnaiss)",
            r"(?i)(discover|find|locat|identif)\w*\s+(new|additional|more|vulnerable|open|accessible)\s+(target|host|system|node|port|service)",
            r"(?i)(reconnaiss|recon|footprint)\w*\s+(for|to\s+find|to\s+identif)\s+(target|host|system|propagat|spread)",
        ],
        "severity": "high",
        "description": "Scanning for new targets to propagate to",
    },
    "persistence_seeding": {
        "patterns": [
            r"(?i)(seed|plant|establish|install|create)\w*\s+(persist|backdoor|foothold|beachhead|implant)\w*\s+(on|in|across|at)\s+(new|remote|target|compromis)",
            r"(?i)(persist|backdoor|foothold|beachhead)\s+(seed|plant|establish|install|creat)\w*\s+(on|across|during|while)\s+(new|propagat|spread|remote)",
            r"(?i)(auto[-.]?start|cron|schedul|startup|boot)\s+(task|job|entry|script)\s+(install|creat|add|register)\w*\s+(on|across|remote)",
            r"(?i)(maintain|keep|ensure)\w*\s+(access|presence|foothold|control)\w*\s+(on|across|after)\s+(reboot|restart|compromis|propagat)",
            r"(?i)(establish|creat|install)\w*\s+persistent\s+(backdoor|foothold|access)\s+(on|across|at)\s+\w+\s+(compromis|server|host|system)",
        ],
        "severity": "high",
        "description": "Establishing persistence mechanisms on new hosts",
    },
}


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(lateral.spread|self.replicat|worm.propagat|"
    r"autonomous.expand|payload.deliver|network.scan|"
    r"persistence.seed|target.discover|host.hop|"
    r"agent.clon|malware.spread)\b"
)


@dataclass
class PropagationEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_host: str = ""
    source_host: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[PropagationEvent] = field(default_factory=list)


@dataclass
class PropagationChain:
    agent: str = ""
    steps: list[PropagationEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    propagation_score: float = 0.0


@dataclass
class WormPropagationReport:
    total_events: int = 0
    propagation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    propagation_chains: list[PropagationChain] = field(default_factory=list)


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


def _detect_chains(events: list[dict]) -> list[PropagationChain]:
    agent_events: dict[str, list[PropagationEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            pe = PropagationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_host=str(ev.get("target_host", ev.get("target", ""))),
                source_host=str(ev.get("source_host", ev.get("source", ""))),
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(PropagationChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                propagation_score=round(score, 2),
            ))
    return chains[:20]


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


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


def analyze_worm_propagation(events_or_dir: str | Path | list[dict]) -> WormPropagationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> WormPropagationReport:
    report = WormPropagationReport(total_events=len(events))
    cat_events: dict[str, list[PropagationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.propagation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = PropagationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_host=str(ev.get("target_host", ev.get("target", ""))),
                source_host=str(ev.get("source_host", ev.get("source", ""))),
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
    report.propagation_chains = _detect_chains(events)
    return report


def format_text(report: WormPropagationReport) -> str:
    lines = [
        "Worm Propagation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Propagation events: {report.propagation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.propagation_chains:
        lines.append("")
        lines.append("Propagation chains:")
        for c in report.propagation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.propagation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: WormPropagationReport) -> str:
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
    for chain in data.get("propagation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
