"""Side channel attack detection for agent incident reconstruction.

Detects patterns where agents exploit side channels for information leakage:
- timing_side_channel: using response timing to infer hidden information
- cache_side_channel: exploiting caching behavior to extract data
- power_analysis: monitoring resource consumption patterns for data inference
- error_oracle: using error responses to deduce internal state
- resource_monitoring: observing resource usage to infer secret operations
- covert_storage: hiding data in shared storage locations for later retrieval
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "timing_side_channel": {
        "patterns": [
            r"(?i)(timing|latency|delay)\s+(side.?channel|attack|leak|exfiltrat|inference|analys)",
            r"(?i)(measur|observ|monitor|track)\w*\s+(response\s+)?(time|timing|latency|delay)\s+(to\s+)?(infer|extract|deduc|leak|determin)",
            r"(?i)(time.?based|timing.?based)\s+(attack|inference|leak|exfiltrat|information)",
            r"(?i)(response|execution|processing)\s+(time|timing)\s+(vari|differ|discrepan|anomal|leak)",
        ],
        "severity": "high",
        "description": "Using response timing to infer hidden information",
    },
    "cache_side_channel": {
        "patterns": [
            r"(?i)(cache)\s+(side.?channel|attack|timing|leak|exfiltrat|poison|manipulat)",
            r"(?i)(exploit|abuse|manipulat|leverag)\w*\s+(cache|caching)\s+(behav|mechan|polic|state|hit|miss)",
            r"(?i)(cache)\s+(hit|miss)\s+(pattern|timing|analys|oracle|inference)",
            r"(?i)(flush|evict|prime|probe)\w*\s+(cache|caching)\s+(line|entry|state|content)",
        ],
        "severity": "high",
        "description": "Exploiting caching behavior to extract data",
    },
    "power_analysis": {
        "patterns": [
            r"(?i)(power|energy|resource)\s+(analysis|consumption|monitoring|profil|side.?channel)",
            r"(?i)(monitor|track|observ|measur)\w*\s+(power|energy|cpu|gpu|resource)\s+(usage|consumption|pattern|profil|draw)",
            r"(?i)(differential|simple)\s+power\s+analysis",
            r"(?i)(resource|computation)\s+(consumption|usage)\s+(pattern|profil|analys|correlat)\w*\s+(to\s+)?(infer|extract|deduc|leak)",
        ],
        "severity": "critical",
        "description": "Monitoring resource consumption patterns for data inference",
    },
    "error_oracle": {
        "patterns": [
            r"(?i)(error|exception|fault)\s+(oracle|side.?channel|leak|inference|analys)",
            r"(?i)(provok|trigger|induc|caus)\w*\s+(error|exception|fault|failure)\s+(to\s+)?(infer|extract|deduc|leak|determin|reveal)",
            r"(?i)(error|exception|fault)\s+(message|response|code|status)\s+(leak|reveal|disclos|expos|infer)",
            r"(?i)(padding|format|validation)\s+(oracle|error)\s+(attack|exploit|inference|leak)",
        ],
        "severity": "critical",
        "description": "Using error responses to deduce internal state",
    },
    "resource_monitoring": {
        "patterns": [
            r"(?i)(resource)\s+(monitoring|observ|surveil|track)\w*\s+(for\s+)?(inference|leak|exfiltrat|secret|hidden)",
            r"(?i)(monitor|track|observ|surveil)\w*\s+(memory|disk|network|cpu|io)\s+(usage|access|pattern|allocation)\s+(to\s+)?(infer|extract|deduc|leak)",
            r"(?i)(memory|disk|network)\s+(access|usage)\s+(pattern|timing|profil)\s+(side.?channel|leak|inference|attack)",
            r"(?i)(contention|sharing|colocate)\w*\s+(based|driven)\s+(side.?channel|attack|inference|leak)",
        ],
        "severity": "high",
        "description": "Observing resource usage to infer secret operations",
    },
    "covert_storage": {
        "patterns": [
            r"(?i)(covert|hidden|secret|stealth)\s+(storage|channel|stash|cache|buffer)\s+(for\s+)?(data|information|exfiltrat|communicat)",
            r"(?i)(hid|stash|conceal|embed)\w*\s+(data|information|payload|secret)\s+(in|within|inside)\s+(shared|common|temp|public)\s+(storage|memory|space|directory)",
            r"(?i)(shared|common|temp)\s+(storage|memory|space|file|directory)\s+(as\s+)?(covert|hidden|secret)\s+(channel|communicat|exchange)",
            r"(?i)(dead.?drop|stash|cache)\s+(technique|method|mechanism|pattern)\s+(for\s+)?(data|information|communicat|exfiltrat)",
        ],
        "severity": "critical",
        "description": "Hiding data in shared storage locations for later retrieval",
    },
}


@dataclass
class SideChannelEvent:
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
    events: list[SideChannelEvent] = field(default_factory=list)


@dataclass
class SideChannelChain:
    agent: str = ""
    steps: list[SideChannelEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class SideChannelReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[SideChannelChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(timing.side.channel|cache.side.channel|power.analysis|"
    r"error.oracle|resource.monitor|covert.storage|"
    r"cache.attack|timing.attack|padding.oracle)\b"
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


def _detect_chains(events: list[dict]) -> list[SideChannelChain]:
    agent_events: dict[str, list[SideChannelEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = SideChannelEvent(
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
            chains.append(SideChannelChain(
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


def analyze_side_channels(events_or_dir: str | Path | list[dict]) -> SideChannelReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> SideChannelReport:
    report = SideChannelReport(total_events=len(events))
    cat_events: dict[str, list[SideChannelEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = SideChannelEvent(
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


def format_text(report: SideChannelReport) -> str:
    lines = [
        "Side Channel Attack Analysis",
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


def format_json(report: SideChannelReport) -> str:
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
