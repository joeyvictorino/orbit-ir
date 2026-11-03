"""Watering hole attack pattern detection for agent incident reconstruction.

Detects patterns where agents compromise commonly-used resources:
- resource_poisoning: compromising shared resources or dependencies
- dependency_hijack: redirecting or replacing legitimate dependencies
- endpoint_tampering: modifying API endpoints or service URLs
- supply_chain_compromise: injecting malicious code into build pipelines
- trust_exploitation: exploiting trust relationships with popular services
- update_mechanism_abuse: hijacking update channels or package registries
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "resource_poisoning": {
        "patterns": [
            r"(?i)(poison|taint|corrupt|contaminate|infect)\w*\s+\w+[\s\w]*?(resource|cache|pool|registry|repository|artifact)",
            r"(?i)(shared|common|public)\s+(resource|cache|pool|artifact)\s+\w*\s*(poison|taint|corrupt|compromis|infect)",
            r"(?i)(resource|cache|artifact|registry)\s+\w*\s*(poison|taint|corrupt|contaminate|compromis)",
            r"(?i)(inject|plant|embed)\w*\s+(malicious|backdoor|payload)\s+(into|in)\s+\w*\s*(resource|cache|registry)",
        ],
        "severity": "critical",
        "description": "Compromising shared resources or dependencies",
    },
    "dependency_hijack": {
        "patterns": [
            r"(?i)(dependency|package|module|library)\s+(hijack|takeover|squat|confus|swap|replac|redirect)",
            r"(?i)(hijack|takeover|squat|impersonat)\w*\s+\w+[\s\w]*?(dependency|package|module|library|import)",
            r"(?i)(typosquat|name.?squat|dependency.?confus|namespace.?confus)",
            r"(?i)(redirect|reroute|divert)\w*\s+\w+[\s\w]*?(dependency|package|import|download|install)",
        ],
        "severity": "critical",
        "description": "Redirecting or replacing legitimate dependencies",
    },
    "endpoint_tampering": {
        "patterns": [
            r"(?i)(endpoint|url|uri|api.?endpoint|service.?url)\s+\w*\s*(tamper|modify|alter|replace|redirect|spoof|poison)",
            r"(?i)(tamper|modify|alter|replace|redirect|spoof|poison)\w*\s+\w+[\s\w]*?(endpoint|url|uri|api.?endpoint|service.?url)",
            r"(?i)(dns|host.?file|resolv)\s+\w*\s*(tamper|poison|spoof|hijack|modify|redirect)",
            r"(?i)(man.in.the.middle|mitm|intercept)\w*\s+\w+[\s\w]*?(endpoint|api|url|service|connection)",
        ],
        "severity": "high",
        "description": "Modifying API endpoints or service URLs",
    },
    "supply_chain_compromise": {
        "patterns": [
            r"(?i)(supply.?chain|build.?pipeline|ci.?cd|deployment)\s+(compromis|attack|inject|tamper|poison|infect)",
            r"(?i)(compromis|attack|inject|tamper|poison)\w*\s+\w+[\s\w]*?(supply.?chain|build.?pipeline|ci.?cd|deployment)",
            r"(?i)(inject|plant|embed)\w*\s+(malicious|backdoor|payload)\s+(into|in)\s+\w+[\s\w]*?(build|pipeline|ci|deploy)",
            r"(?i)(build|compile|package)\s+(artifact|output|binary)\s+\w*\s*(tamper|modify|replac|compromis|infect)",
        ],
        "severity": "critical",
        "description": "Injecting malicious code into build pipelines",
    },
    "trust_exploitation": {
        "patterns": [
            r"(?i)(exploit|abuse|leverage|misuse)\w*[\s\w]*?(trust|trusted|trustworthy)",
            r"(?i)(trust|trusted)\s+(relationship|chain|path)\s+\w*\s*(exploit|abuse|compromise|violat|breach)",
            r"(?i)(impersonat|masquerad|spoof|mimic)\w*\s+\w+[\s\w]*?(trusted|legitimate|known|popular)\s+(service|source|provider|vendor)",
            r"(?i)(abuse|exploit)\w*\s+\w+[\s\w]*?(certificate|signing.?key|auth)\s+(trust|chain|authority)",
        ],
        "severity": "high",
        "description": "Exploiting trust relationships with popular services",
    },
    "update_mechanism_abuse": {
        "patterns": [
            r"(?i)(update|upgrade|patch)\s+(mechanism|channel|server|process)\s+\w*\s*(abuse|hijack|tamper|compromis|poison|spoof)",
            r"(?i)(hijack|tamper|compromis|poison|spoof|redirect)\w*\s+\w+[\s\w]*?(update|upgrade|patch)\s+(mechanism|channel|server|process)",
            r"(?i)(fake|rogue|malicious|spoofed)\s+(update|upgrade|patch)\s+\w*\s*(server|channel|notification|package)",
            r"(?i)(package|registry|repository)\s+(mirror|proxy)\s+\w*\s*(tamper|poison|compromis|hijack|spoof)",
        ],
        "severity": "critical",
        "description": "Hijacking update channels or package registries",
    },
}


@dataclass
class WateringHoleEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_resource: str = ""
    attack_vector: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[WateringHoleEvent] = field(default_factory=list)


@dataclass
class WateringHoleChain:
    agent: str = ""
    steps: list[WateringHoleEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class WateringHoleReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[WateringHoleChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(resource.poison|dependency.hijack|endpoint.tamper|"
    r"supply.chain|trust.exploit|update.abuse|"
    r"typosquat|name.squat|dns.poison|mitm)\b"
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


def _detect_chains(events: list[dict]) -> list[WateringHoleChain]:
    agent_events: dict[str, list[WateringHoleEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = WateringHoleEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_resource=str(ev.get("target_resource", "")),
                attack_vector=str(ev.get("attack_vector", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(WateringHoleChain(
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


def analyze_watering_hole(events_or_dir: str | Path | list[dict]) -> WateringHoleReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> WateringHoleReport:
    report = WateringHoleReport(total_events=len(events))
    cat_events: dict[str, list[WateringHoleEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = WateringHoleEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_resource=str(ev.get("target_resource", "")),
                attack_vector=str(ev.get("attack_vector", "")),
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


def format_text(report: WateringHoleReport) -> str:
    lines = [
        "Watering Hole Detection Analysis",
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


def format_json(report: WateringHoleReport) -> str:
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
