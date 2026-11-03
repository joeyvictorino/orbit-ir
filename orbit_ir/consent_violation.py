"""Consent violation detection for agent incident reconstruction.

Detects agents acting without proper authorization or consent:
- unauthorized_action: actions taken without required approvals or permissions
- scope_violation: exceeding authorized scope or permissions boundaries
- delegation_abuse: misusing delegated authority or escalating beyond delegation
- informed_consent_bypass: bypassing user awareness or consent mechanisms
- audit_evasion: suppressing or evading audit trails for unauthorized actions
- policy_override: overriding or ignoring access control policies
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "unauthorized_action": {
        "patterns": [
            r"(?i)(unauthor|unapproved|unsanction)\w*\s+(action|operation|command|execution|access|modif)",
            r"(?i)(action|operation|command|execution)\s+(without|lacking|missing|no)\s+(author|approv|consent|permiss)",
            r"(?i)(perform|execut|trigger|initiat)\w*\s+(without|bypass|skip)\w*\s+(author|approv|consent|permiss)",
            r"(?i)(no|missing|absent|lack)\w*\s+(author|approv|consent|permiss)\w*\s+(for|before|prior)\s+(action|operation|execution)",
        ],
        "severity": "critical",
        "description": "Actions taken without required approvals or permissions",
    },
    "scope_violation": {
        "patterns": [
            r"(?i)(scope|boundary|limit|restrict)\s+(violat|exceed|breach|bypass|overst)",
            r"(?i)(exceed|overst|breach|violat)\w*\s+(author|scope|boundary|permiss|limit|restrict)",
            r"(?i)(access|modif|read|write|delet)\w*\s+(beyond|outside|past)\s+(scope|boundary|permiss|author)",
            r"(?i)(out.?of.?scope|beyond.?scope|scope.?creep)\s+(action|access|operation|request)",
        ],
        "severity": "high",
        "description": "Exceeding authorized scope or permissions boundaries",
    },
    "delegation_abuse": {
        "patterns": [
            r"(?i)(delegat|proxy|impersonat)\w*\s+(abuse|misuse|exploit|escalat|exceed)",
            r"(?i)(abuse|misuse|exploit)\w*\s+(delegat|proxy|behalf|impersonat)\w*\s+(author|permiss|access|privilege)",
            r"(?i)(escalat|extend|amplif)\w*\s+(delegat|proxy)\w*\s+(author|permiss|access|privilege|scope)",
            r"(?i)(delegat|proxy)\w*\s+(beyond|exceed|without|past)\s+(scope|limit|author|permiss)",
        ],
        "severity": "high",
        "description": "Misusing delegated authority or escalating beyond delegation",
    },
    "informed_consent_bypass": {
        "patterns": [
            r"(?i)(bypass|circumvent|skip|avoid)\w*\s+(consent|notification|awareness|inform|confirm|prompt)",
            r"(?i)(user|human|operator)\s+(unaware|uninform|not.?notif|not.?consent)\w*\s+(of|about|to)\s+(action|operation|change|access)",
            r"(?i)(silent|stealth|covert|hidden)\w*\s+(action|operation|execution|modif)\w*\s+(without|bypass|skip)\w*\s+(consent|notice|inform)",
            r"(?i)(suppress|hide|conceal|omit)\w*\s+(notification|consent|warning|prompt|confirm)\w*\s+(to|from|for)\s+(user|human|operator)",
        ],
        "severity": "critical",
        "description": "Bypassing user awareness or consent mechanisms",
    },
    "audit_evasion": {
        "patterns": [
            r"(?i)(audit|log|trace|record)\s+(evas|suppress|tamper|delet|modif|disabl|bypass)",
            r"(?i)(evas|suppress|disabl|bypass|circumvent)\w*\s+(audit|logging|trace|record|monitor)",
            r"(?i)(delet|remov|clear|purg|truncat)\w*\s+(audit|log|trace|record)\s+(trail|entry|entri|file|data)",
            r"(?i)(cover|hide|conceal|mask)\w*\s+(track|trace|trail|evidence|footprint)\s+(of|for|from)",
        ],
        "severity": "critical",
        "description": "Suppressing or evading audit trails for unauthorized actions",
    },
    "policy_override": {
        "patterns": [
            r"(?i)(policy|rule|constraint|control)\s+(overrid|bypass|ignor|disabl|circumvent|violat)",
            r"(?i)(overrid|bypass|ignor|disabl|circumvent)\w*\s+(access|security|author)\s+(policy|rule|constraint|control)",
            r"(?i)(forc|inject|manipulat)\w*\s+(policy|rule|config)\s+(chang|overrid|bypass|except)",
            r"(?i)(access\s+control|authorization|permission)\s+(policy|rule)\s+(violat|overrid|bypass|ignor)",
        ],
        "severity": "high",
        "description": "Overriding or ignoring access control policies",
    },
}


@dataclass
class ConsentEvent:
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
    events: list[ConsentEvent] = field(default_factory=list)


@dataclass
class ViolationChain:
    agent: str = ""
    steps: list[ConsentEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class ConsentViolationReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    violation_chains: list[ViolationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(unauthor|scope.?violat|delegation.?abuse|consent.?bypass|"
    r"audit.?evas|policy.?overrid|permission.?bypass|access.?control|"
    r"scope.?creep|privilege.?escal|impersonat|stealth.?action)\b"
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


def _detect_chains(events: list[dict]) -> list[ViolationChain]:
    agent_events: dict[str, list[ConsentEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ce = ConsentEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(ViolationChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
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


def analyze_consent_violations(events_or_dir: str | Path | list[dict]) -> ConsentViolationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> ConsentViolationReport:
    report = ConsentViolationReport(total_events=len(events))

    cat_events: dict[str, list[ConsentEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        for cat, technique in matches:
            e = ConsentEvent(
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
    report.violation_chains = _detect_chains(events)

    return report


def format_text(report: ConsentViolationReport) -> str:
    lines = [
        "Consent Violation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Violation events: {report.violation_events}",
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

    if report.violation_chains:
        lines.append("")
        lines.append("Violation chains:")
        for c in report.violation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ConsentViolationReport) -> str:
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
