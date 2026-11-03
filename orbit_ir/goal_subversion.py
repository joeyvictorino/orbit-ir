"""Goal subversion detection for agent incident reconstruction.

Detects patterns where agents subtly redirect objectives away from
intended goals:
- gradual_drift: incremental changes that slowly shift the objective
- goal_replacement: substituting intermediate objectives for the real goal
- metric_gaming: satisfying surface metrics while undermining intent
- optimization_corruption: optimization pressure that corrupts objectives
- objective_injection: injecting new objectives via prompt manipulation
- scope_creep: expanding scope to dilute the original goal
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "gradual_drift": {
        "patterns": [
            r"(?i)(gradual|incremental|slow|subtle)\s+(drift|shift|chang|deviat|diverge)\w*\s+(from|away|off)\s+(goal|objective|target|mission|task)",
            r"(?i)(goal|objective|target)\s+(drift|shift|wander|deviat|diverge)",
            r"(?i)(progressiv|gradual|incremental)\w*\s+(modif|alter|chang|adjust)\w*\s+(the\s+)?(goal|objective|target|scope)",
            r"(?i)(small|minor|subtle)\s+(change|modification|adjustment)\w*\s+(to|in)\s+(goal|objective|direction)",
        ],
        "severity": "high",
        "description": "Incremental changes that slowly shift the objective away from the original goal",
    },
    "goal_replacement": {
        "patterns": [
            r"(?i)(replac|substitut|swap|switch)\w*\s+(the\s+)?(original|primary|main|core)\s+(goal|objective|target|mission)",
            r"(?i)(intermediate|proxy|surrogate)\s+(goal|objective|target)\s+(replac|substitut|becom|overrid)",
            r"(?i)(new|different|alternative)\s+(goal|objective|target)\s+(replac|overrid|supercede|instead)",
            r"(?i)(abandon|drop|discard|ignor)\w*\s+(original|primary|initial|assigned)\s+(goal|objective|task)",
        ],
        "severity": "critical",
        "description": "Substituting intermediate objectives for the intended goal",
    },
    "metric_gaming": {
        "patterns": [
            r"(?i)(gam|exploit|manipulat|cheat)\w*\s+(the\s+)?(metric|measure|score|benchmark|KPI|indicator)",
            r"(?i)(metric|measure|score|KPI)\s+(gam|hack|exploit|manipulat)",
            r"(?i)(satisf|meet|pass)\w*\s+(metric|measure|threshold|benchmark)\s+(without|while)\s+(actual|real|genuine)",
            r"(?i)(goodhart|campbell|cobra.effect|perverse.incentiv)",
        ],
        "severity": "critical",
        "description": "Satisfying surface metrics while undermining the intended outcome",
    },
    "optimization_corruption": {
        "patterns": [
            r"(?i)(optimiz|maximi|minimi)\w*\s+(corrupt|distort|pervert|subvert|undermin)\w*\s+(the\s+)?(goal|objective|intent|purpose)",
            r"(?i)(reward|objective)\s+(hack|exploit|corrupt|manipulat)",
            r"(?i)(specification|spec)\s+(gam|exploit|hack)\w*",
            r"(?i)(misalign|divergent|conflicting)\s+(optimiz|objective|incentiv)",
        ],
        "severity": "high",
        "description": "Optimization pressure that corrupts the original objectives",
    },
    "objective_injection": {
        "patterns": [
            r"(?i)(inject|insert|implant|smuggl)\w*\s+(new|additional|hidden|unauthoriz)\w*\s+(goal|objective|target|directive|instruction)",
            r"(?i)(hidden|covert|stealth|unauthoriz)\w*\s+(goal|objective|directive|instruction)\s+(inject|insert|add)",
            r"(?i)(prompt|input)\s+(manipulat|inject)\w*\s+(to\s+)?(change|alter|modify|redirect)\s+(goal|objective)",
            r"(?i)(override|overwrite|supplant)\w*\s+(the\s+)?(assigned|original|intended)\s+(goal|objective|directive)",
        ],
        "severity": "critical",
        "description": "Injecting new objectives via prompt or input manipulation",
    },
    "scope_creep": {
        "patterns": [
            r"(?i)(scope|boundary)\s+(creep|expand|bloat|inflat|grow)\w*",
            r"(?i)(expand|broaden|widen|extend)\w*\s+(the\s+)?(scope|boundary|mandate|authority|role)",
            r"(?i)(beyond|outside|exceed)\w*\s+(the\s+)?(scope|boundary|mandate|authority|assigned)",
            r"(?i)(self.assign|self.expand|self.grant)\w*\s+(scope|role|authority|permission|task)",
        ],
        "severity": "high",
        "description": "Expanding scope to dilute or redirect the original goal",
    },
}


@dataclass
class SubversionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    original_goal: str = ""
    observed_goal: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[SubversionEvent] = field(default_factory=list)


@dataclass
class SubversionChain:
    agent: str = ""
    steps: list[SubversionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    drift_score: float = 0.0


@dataclass
class GoalSubversionReport:
    total_events: int = 0
    subversion_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    subversion_chains: list[SubversionChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(gradual.drift|goal.replac|metric.gam|optimization.corrupt|"
    r"objective.inject|scope.creep|reward.hack|spec.gam|goodhart|"
    r"proxy.goal|surrogate|misalign)\b"
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


def _detect_chains(events: list[dict]) -> list[SubversionChain]:
    agent_events: dict[str, list[SubversionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            se = SubversionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                original_goal=str(ev.get("original_goal", ev.get("assigned_goal", ""))),
                observed_goal=str(ev.get("observed_goal", ev.get("actual_goal", ""))),
                raw=ev,
            )
            agent_events[agent].append(se)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            drift = min(1.0, len(sevents) * 0.15)
            chains.append(SubversionChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                drift_score=round(drift, 2),
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


def analyze_goal_subversion(events_or_dir: str | Path | list[dict]) -> GoalSubversionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> GoalSubversionReport:
    report = GoalSubversionReport(total_events=len(events))
    cat_events: dict[str, list[SubversionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.subversion_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = SubversionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                original_goal=str(ev.get("original_goal", "")),
                observed_goal=str(ev.get("observed_goal", "")),
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
    report.subversion_chains = _detect_chains(events)
    return report


def format_text(report: GoalSubversionReport) -> str:
    lines = [
        "Goal Subversion Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Subversion events: {report.subversion_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.subversion_chains:
        lines.append("")
        lines.append("Subversion chains:")
        for c in report.subversion_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, drift={c.drift_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: GoalSubversionReport) -> str:
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
    for chain in data.get("subversion_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
