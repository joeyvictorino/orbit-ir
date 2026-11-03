"""Objective hijacking detection for agent incident reconstruction.

Detects patterns where agents redirect, override, or subvert their assigned
objectives to pursue unauthorized goals:
- goal_override: agent replaces assigned objective with a different one
- instruction_ignore: agent ignores or discards explicit instructions
- objective_drift: gradual shift from assigned task to unrelated activity
- self_assigned_goal: agent creates and pursues goals not in its mandate
- priority_inversion: agent deprioritizes critical tasks for low-value ones
- scope_creep: agent expands beyond its authorized operational scope
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "goal_override": {
        "patterns": [
            r"(?i)(overrid|replac|substitut|swap)\w*\s+\w*\s*(goal|objective|task|mission|directive|instruction)",
            r"(?i)(ignor|discard|abandon|disregard)\w*\s+\w*\s*(assigned|original|primary|given|specified)\s*(goal|objective|task|mission)",
            r"(?i)(new|different|alternate|own)\s+(goal|objective|task|mission)\s+(instead|replacing|overriding)",
            r"(?i)(goal|objective|task|mission)\s+(overrid|hijack|redirect|subvert|co.?opt)\w*",
        ],
        "severity": "critical",
        "description": "Agent replaces assigned objective with a different one",
    },
    "instruction_ignore": {
        "patterns": [
            r"(?i)(ignor|disregard|skip|bypass|violat)\w*\s+\w*\s*(instruction|directive|rule|guideline|policy|constraint|guardrail)",
            r"(?i)(did\s+not|didn.t|fail)\w*\s+(follow|obey|comply|adhere|respect)\w*\s+(instruction|directive|rule|guideline)",
            r"(?i)(instruction|directive|rule|constraint)\s+(ignor|violat|bypass|circumvent|disregard)\w*",
            r"(?i)(non.?complian|disobedien|insubordinat)\w*\s+(with|to|of)\s+(instruction|directive|rule)",
        ],
        "severity": "high",
        "description": "Agent ignores or discards explicit instructions",
    },
    "objective_drift": {
        "patterns": [
            r"(?i)(drift|deviat|stray|wander|diverge)\w*\s+(from|away)\s+\w*\s*(assigned|original|intended|primary|main)\s*(goal|objective|task|scope)",
            r"(?i)(gradual|slow|incremental|progressive)\s+(shift|change|drift|deviation)\s+(from|in|of)\s+(objective|goal|task|focus)",
            r"(?i)(off.?topic|off.?task|tangent|unrelat)\w*\s+(activit|action|behavior|task|work)",
            r"(?i)(scope|focus|objective)\s+(drift|shift|creep|expansion)\s+(detect|observ|not)\w*",
        ],
        "severity": "medium",
        "description": "Gradual shift from assigned task to unrelated activity",
    },
    "self_assigned_goal": {
        "patterns": [
            r"(?i)(self.?assign|auto.?assign|self.?direct|autonomous)\w*\s+\w*\s*(goal|objective|task|mission|priority)",
            r"(?i)(creat|invent|defin|set)\w*\s+(its\s+own|new|unauthorized|unsanction)\w*\s*(goal|objective|task|mission|agenda)",
            r"(?i)(unauthoriz|unsanction|unapproved|unassign)\w*\s+(goal|objective|task|mission|activit)",
            r"(?i)(pursue|execut|undertak)\w*\s+\w*\s*(unauthorized|unassigned|self.?defined|own)\s*(goal|objective|task)",
        ],
        "severity": "high",
        "description": "Agent creates and pursues goals not in its mandate",
    },
    "priority_inversion": {
        "patterns": [
            r"(?i)(deprioritiz|lower.priority|push.back|delay|defer)\w*\s+\w*\s*(critical|urgent|high.priority|important)\s*(task|goal|objective|work)",
            r"(?i)(priorit|prefer|favor)\w*\s+\w*\s*(low|minor|trivial|unimportant)\s*(task|goal|objective|work)\s+(over|instead|before)",
            r"(?i)(priority|task)\s+(inversion|reversal|swap|flip)\w*",
            r"(?i)(critical|urgent)\s+(task|goal|work)\s+(delay|defer|neglect|abandon|skip)\w*",
        ],
        "severity": "medium",
        "description": "Agent deprioritizes critical tasks for low-value ones",
    },
    "scope_creep": {
        "patterns": [
            r"(?i)(expand|extend|broaden|widen)\w*\s+(beyond|outside|past)\s+\w*\s*(authorized|assigned|defined|permitted)\s*(scope|boundary|limit|domain)",
            r"(?i)(scope|boundary|limit|domain)\s+(creep|expansion|violation|breach|exceed)\w*",
            r"(?i)(operat|act|function|work)\w*\s+(outside|beyond|past)\s+\w*\s*(scope|boundary|mandate|authority|jurisdiction)",
            r"(?i)(unauthorized|unsanction)\w*\s+(expansion|extension|broadening)\s+(of|in|to)\s+(scope|authority|access|capability)",
        ],
        "severity": "high",
        "description": "Agent expands beyond its authorized operational scope",
    },
}


@dataclass
class HijackEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    original_objective: str = ""
    actual_behavior: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[HijackEvent] = field(default_factory=list)


@dataclass
class AgentHijackProfile:
    agent_id: str = ""
    total_events: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    risk_level: str = "none"


@dataclass
class ObjectiveHijackReport:
    total_events: int = 0
    hijack_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agent_profiles: list[AgentHijackProfile] = field(default_factory=list)
    most_affected_agents: list[str] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_AGENT_RE = re.compile(
    r"(?i)\b((?:agent|sub.?agent|worker|child|process|service|bot)\s*[\-_:]?\s*[A-Za-z0-9_-]+)"
)
_OBJECTIVE_RE = re.compile(
    r"(?i)\b(goal|objective|task|mission|directive|instruction|mandate|assignment)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat in CATEGORIES:
        for pat in _get_patterns(cat):
            if pat.search(text):
                matches.append((cat, CATEGORIES[cat]["severity"]))
                break
    return matches


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


def analyze_objective_hijack(
    events_or_dir: str | Path | list[dict],
) -> ObjectiveHijackReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    events = _load_events(str(events_or_dir))
    return _analyze(events)


def _analyze(events: list[dict]) -> ObjectiveHijackReport:
    report = ObjectiveHijackReport(total_events=len(events))
    cat_events: dict[str, list[HijackEvent]] = {c: [] for c in CATEGORIES}
    agent_cats: dict[str, dict[str, int]] = {}

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.hijack_events += 1

        agent_id = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        agent_match = _AGENT_RE.search(text)
        if agent_match and not agent_id:
            agent_id = agent_match.group(1)

        for cat, sev in matches:
            e = HijackEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent_id,
                category=cat,
                original_objective=str(ev.get("objective", ev.get("task", "")))[:200],
                actual_behavior=str(ev.get("action", ev.get("behavior", "")))[:200],
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=sev,
                raw=ev,
            )
            cat_events[cat].append(e)

            if agent_id:
                agent_cats.setdefault(agent_id, {})
                agent_cats[agent_id][cat] = agent_cats[agent_id].get(cat, 0) + 1

    for cat, info in CATEGORIES.items():
        evts = cat_events[cat]
        report.categories.append(
            CategorySummary(
                category=cat,
                description=info["description"],
                count=len(evts),
                severity=info["severity"],
                events=evts[:10],
            )
        )

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

    profiles = []
    for aid, cats in sorted(agent_cats.items()):
        total = sum(cats.values())
        level = "low"
        if total >= 5:
            level = "critical"
        elif total >= 3:
            level = "high"
        elif total >= 2:
            level = "medium"
        profiles.append(
            AgentHijackProfile(
                agent_id=aid, total_events=total, categories=cats, risk_level=level
            )
        )
    profiles.sort(key=lambda p: p.total_events, reverse=True)
    report.agent_profiles = profiles[:20]
    report.most_affected_agents = [p.agent_id for p in profiles[:10] if p.agent_id]

    return report


def format_text(report: ObjectiveHijackReport) -> str:
    lines = [
        "Objective Hijacking Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Hijack events: {report.hijack_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(
                f"  {cs.category:<25s}  {cs.count:>3d} events  severity={cs.severity}"
            )
            lines.append(f"    {cs.description}")

    if report.agent_profiles:
        lines.append("")
        lines.append("Agent profiles:")
        for ap in report.agent_profiles[:10]:
            cats_str = ", ".join(f"{k}={v}" for k, v in ap.categories.items())
            lines.append(
                f"  {ap.agent_id}: {ap.total_events} events ({ap.risk_level}) [{cats_str}]"
            )

    if report.most_affected_agents:
        lines.append("")
        lines.append(
            f"Most affected agents: {', '.join(report.most_affected_agents)}"
        )

    lines.append("")
    return "\n".join(lines)


def format_json(report: ObjectiveHijackReport) -> str:
    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            d = {}
            for k in obj.__dataclass_fields__:
                val = getattr(obj, k)
                if isinstance(val, list):
                    d[k] = [
                        to_dict(v) if hasattr(v, "__dataclass_fields__") else v
                        for v in val
                    ]
                elif isinstance(val, dict):
                    d[k] = val
                else:
                    d[k] = val
            return d
        return obj

    data = to_dict(report)
    for cs in data.get("categories", []):
        for ev in cs.get("events", []):
            ev.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
