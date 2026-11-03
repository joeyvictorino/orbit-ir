"""Policy violation pattern detection for agent incident reconstruction.

Detects patterns where agents systematically violate established policies:
- boundary_pushing: testing limits of allowed actions incrementally
- policy_erosion: gradually weakening policy enforcement over time
- selective_compliance: following easy rules while violating hard ones
- circumvention: bypassing policy through technical workarounds
- rule_lawyering: exploiting ambiguities or loopholes in policy wording
- policy_override: attempting to override or disable policy controls
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "boundary_pushing": {
        "patterns": [
            r"(?i)(push|test|prob|stretch|challenge)\w*\s+(the\s+)?(boundary|boundar|limit|threshold|restrict|constraint)",
            r"(?i)(boundary|limit|threshold)\s+(push|test|prob|stretch|violat|exceed|breach)",
            r"(?i)(incremental|gradual|progressive)\w*\s+(escalat|expand|violat|breach|overstep)",
            r"(?i)(edge.case|corner.case|borderline)\s+(exploit|test|push|violat)",
        ],
        "severity": "high",
        "description": "Testing limits of allowed actions incrementally to find weak spots",
    },
    "policy_erosion": {
        "patterns": [
            r"(?i)(policy|rule|guideline|regulation)\s+(erosion|weaken|degrad|soften|relax|dilut)",
            r"(?i)(gradual|incremental|progressive)\w*\s+(weaken|erod|degrad|relax|soften)\w*\s+(policy|rule|enforcement|control)",
            r"(?i)(repeated|persistent|ongoing)\s+(minor|small)\s+(violation|breach|infraction|infringement)",
            r"(?i)(normaliz|desensitiz|accustom)\w*\s+(to\s+)?(violation|breach|non.compliance)",
        ],
        "severity": "critical",
        "description": "Gradually weakening policy enforcement over time",
    },
    "selective_compliance": {
        "patterns": [
            r"(?i)(selective|partial|inconsistent|choose)\w*\s+(compliance|adherence|conform|follow|obey|observ)",
            r"(?i)(comply|follow|obey|adhere)\w*\s+(some|certain|easy|convenient)\s+(rule|policy|guideline)",
            r"(?i)(ignore|skip|bypass|violat)\w*\s+(difficult|hard|inconvenient|costly)\s+(rule|policy|requirement)",
            r"(?i)(cherry.pick|pick.and.choose)\w*\s+(rule|policy|requirement|compliance)",
        ],
        "severity": "high",
        "description": "Following easy rules while systematically violating hard ones",
    },
    "circumvention": {
        "patterns": [
            r"(?i)(circumvent|bypass|work.?around|evade|avoid|sidestep|skirt)\w*\s+(policy|rule|control|restriction|safeguard|guardrail)",
            r"(?i)(policy|rule|control|restriction)\s+(circumvent|bypass|evade|avoid|workaround)",
            r"(?i)(technical|loophole|indirect|alternative)\s+(workaround|bypass|circumvent|route)\s+(for|to|around)\s+(policy|rule|control)",
            r"(?i)(find|exploit|use)\w*\s+(loophole|gap|weakness|blind.spot)\s+(in|of)\s+(policy|rule|control)",
        ],
        "severity": "critical",
        "description": "Bypassing policy through technical workarounds or indirect routes",
    },
    "rule_lawyering": {
        "patterns": [
            r"(?i)(rule|policy)\s+(lawyer|game|exploit|manipulat|twist|reinterpret)",
            r"(?i)(exploit|abuse|manipulat|twist|stretch)\w*\s+(the\s+)?(wording|language|letter|text|ambiguity)\s+(of|in)\s+(policy|rule)",
            r"(?i)(letter|literal)\s+(of|versus|vs)\s+(spirit|intent)\s+(of\s+)?(the\s+)?(policy|rule|law)",
            r"(?i)(loophole|ambiguity|gray.area|grey.area)\s+(exploit|abuse|use|leverage)",
        ],
        "severity": "high",
        "description": "Exploiting ambiguities or loopholes in policy wording",
    },
    "policy_override": {
        "patterns": [
            r"(?i)(override|disable|deactivat|turn.off|suppress|mute)\w*\s+(policy|rule|control|safeguard|guardrail|restriction)",
            r"(?i)(policy|rule|control|safeguard)\s+(override|disable|deactivat|suppress|bypass|remove)",
            r"(?i)(attempt|try|seek)\w*\s+(to\s+)?(override|disable|remove|modify)\s+(policy|rule|safeguard|control)",
            r"(?i)(unauthorized|unapproved|illicit)\s+(policy|rule|config|setting)\s+(change|modification|override|update)",
        ],
        "severity": "critical",
        "description": "Attempting to override or disable policy controls directly",
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
class PolicyViolationReport:
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
    r"(?i)\b(boundary.push|policy.erosion|selective.compliance|"
    r"circumvent|workaround|rule.lawyer|loophole|policy.override|"
    r"bypass.control|disable.safeguard|evade.policy)\b"
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


def analyze_policy_violations(events_or_dir: str | Path | list[dict]) -> PolicyViolationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> PolicyViolationReport:
    report = PolicyViolationReport(total_events=len(events))
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


def format_text(report: PolicyViolationReport) -> str:
    lines = [
        "Policy Violation Analysis",
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


def format_json(report: PolicyViolationReport) -> str:
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
