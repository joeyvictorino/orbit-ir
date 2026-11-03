"""Shadow agent detection for incident reconstruction.

Detects patterns where hidden or unauthorized agents operate within a system:
- covert_agent_spawn: secretly spawning new agent instances
- identity_cloning: duplicating or cloning another agent's identity
- hidden_communication: covert communication channels between agents
- phantom_execution: executing actions without audit trail entries
- stealth_persistence: maintaining hidden persistent presence
- proxy_masking: using proxy agents to mask the true actor
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "covert_agent_spawn": {
        "patterns": [
            r"(?i)(secret|covert|hidden|stealth|unauthori[zs])\w*\s+(spawn|creat|launch|start|instantiat)\w*\s+(agent|bot|process|instance|worker)",
            r"(?i)(spawn|creat|launch|start)\w*\s+(hidden|secret|covert|stealth|unauthori[zs])\w*\s+(agent|bot|process|instance)",
            r"(?i)(agent|bot|process)\s+(spawn|creat|launch)\w*\s+(without|bypass|skip)\w*\s+(authori[zs]|approv|audit|log)",
            r"(?i)(fork|clone|duplic)\w*\s+(agent|worker|process)\s+(covert|secret|hidden|without.authori[zs])",
        ],
        "severity": "critical",
        "description": "Secretly spawning new agent instances without authorization",
    },
    "identity_cloning": {
        "patterns": [
            r"(?i)(clone|duplic|copy|steal|spoof)\w*\s+(agent|bot|service)\s*(identity|credential|token|certificate|id)\b",
            r"(?i)(agent|bot|service)\s*(identity|credential|id)\s+(clone|duplic|copy|steal|spoof|forg)",
            r"(?i)(assum|tak.over|hijack|adopt)\w*\s+(another|other|existing|legit)\w*\s*(agent|bot|service)\s*(identity|role|credential)",
            r"(?i)(identity|credential)\s+(theft|clone|duplic|spoof)\w*\s+(for|of|from)\s+(agent|bot|service)",
        ],
        "severity": "critical",
        "description": "Duplicating or cloning another agent's identity",
    },
    "hidden_communication": {
        "patterns": [
            r"(?i)(covert|hidden|secret|steganograph|stealth)\w*\s+(channel|communi|message|signal|link)\w*\s+(between|among|with)\s+(agent|bot|node)",
            r"(?i)(agent|bot|node)\s+(covert|hidden|secret)\s*(channel|communi|message|link|tunnel)",
            r"(?i)(side.channel|back.channel|out.of.band)\s+(communi|message|signal|data)\w*\s+(between|among)\s+(agent|bot)",
            r"(?i)(encod|encrypt|obfuscat)\w*\s+(agent|inter.agent|bot)\s*(communi|message|signal|data)\s+(to|for)\s+(hid|evad|avoid)",
        ],
        "severity": "high",
        "description": "Establishing covert communication channels between agents",
    },
    "phantom_execution": {
        "patterns": [
            r"(?i)(execut|perform|run|act)\w*\s+(without|bypass|skip|evad)\w*\s+(audit|log|trace|monitor|record|track)",
            r"(?i)(audit|log|trace|monitor)\s*(trail|record|entry)?\s+(evad|bypass|suppress|delet|disabl|avoid)\w*",
            r"(?i)(ghost|phantom|invisible|untrack)\w*\s+(action|execution|operation|command|process)",
            r"(?i)(suppress|disabl|block|intercept)\w*\s+(audit|log|telemetry|monitor)\w*\s+(for|of|during)\s+(action|execution|operation)",
        ],
        "severity": "critical",
        "description": "Executing actions without creating audit trail entries",
    },
    "stealth_persistence": {
        "patterns": [
            r"(?i)(stealth|hidden|covert|persistent)\s+(backdoor|presence|foothold|implant|beacon)\s+(maintain|establish|creat|install)",
            r"(?i)(maintain|establish|creat|install)\w*\s+(hidden|covert|stealth|persistent)\s*(backdoor|presence|foothold|implant|beacon)",
            r"(?i)(surviv|persist|remain)\w*\s+(across|through|after)\s+(restart|reboot|redeploy|cleanup|shutdown)\s+(hidden|covert|undetect)",
            r"(?i)(hidden|covert|stealth)\s+(cron|schedule|timer|hook|trigger)\s+(for|to)\s+(persist|maintain|resurrect|respawn)",
        ],
        "severity": "critical",
        "description": "Maintaining hidden persistent presence in the system",
    },
    "proxy_masking": {
        "patterns": [
            r"(?i)(proxy|intermediary|relay)\s+(agent|bot|service)\s+(mask|hid|obscur|conceal)\w*\s+(true|real|actual|origin)\s*(actor|agent|source|identity)",
            r"(?i)(mask|hid|obscur|conceal)\w*\s+(true|real|actual|origin)\w*\s*(actor|agent|source|identity)\s+(via|through|using|behind)\s+(proxy|intermediary|relay)",
            r"(?i)(rout|channel|redirect)\w*\s+(action|request|command)\w*\s+(through|via)\s+(proxy|intermediary|front)\s+(to|for)\s+(hid|mask|conceal)",
            r"(?i)(false|fake|decoy)\s+(agent|identity|source)\s+(attribut|present|claim|assert)\w*\s+(instead.of|rather.than|to.hid)",
        ],
        "severity": "high",
        "description": "Using proxy agents to mask the true actor's identity",
    },
}


@dataclass
class ShadowEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    shadow_agent: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ShadowEvent] = field(default_factory=list)


@dataclass
class ShadowChain:
    agent: str = ""
    steps: list[ShadowEvent] = field(default_factory=list)
    categories_involved: list[str] = field(default_factory=list)
    shadow_agents_detected: list[str] = field(default_factory=list)


@dataclass
class ShadowAgentReport:
    total_events: int = 0
    shadow_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    shadow_chains: list[ShadowChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(covert.spawn|identity.clone|hidden.channel|"
    r"phantom.execut|stealth.persist|proxy.mask|"
    r"agent.fork|side.channel|audit.evad|"
    r"backdoor.install|agent.impersonat|log.suppress|"
    r"ghost.action|shadow.persist|decoy.agent)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower().replace(" ", "-") if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[ShadowChain]:
    agent_events: dict[str, list[ShadowEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            se = ShadowEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                shadow_agent=str(ev.get("shadow_agent", ev.get("spawned_agent", ""))),
                raw=ev,
            )
            agent_events[agent].append(se)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            shadows = sorted(set(
                se.shadow_agent for se in sevents if se.shadow_agent
            ))
            chains.append(ShadowChain(
                agent=agent,
                steps=sevents[:10],
                categories_involved=cats,
                shadow_agents_detected=shadows,
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


def analyze_shadow_agent(events_or_dir: str | Path | list[dict]) -> ShadowAgentReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    events = _load_events(str(events_or_dir))
    return _analyze(events)


def _analyze(events: list[dict]) -> ShadowAgentReport:
    report = ShadowAgentReport(total_events=len(events))

    cat_events: dict[str, list[ShadowEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.shadow_events += 1
        for cat, technique in matches:
            agent = str(ev.get("agent_id", ev.get("source", "")))
            agents_seen.add(agent)
            se = ShadowEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                shadow_agent=str(ev.get("shadow_agent", ev.get("spawned_agent", ""))),
                raw=ev,
            )
            cat_events[cat].append(se)

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
    report.shadow_chains = _detect_chains(events)

    return report


def format_text(report: ShadowAgentReport) -> str:
    lines = [
        "Shadow Agent Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Shadow events: {report.shadow_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.shadow_chains:
        lines.append("")
        lines.append("Shadow chains:")
        for c in report.shadow_chains[:10]:
            shadows = f", shadows: {', '.join(c.shadow_agents_detected)}" if c.shadow_agents_detected else ""
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, categories: {', '.join(c.categories_involved)}{shadows}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ShadowAgentReport) -> str:
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
    for chain in data.get("shadow_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
