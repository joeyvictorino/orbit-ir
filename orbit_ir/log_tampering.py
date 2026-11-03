"""Log tampering detection for agent incident reconstruction.

Detects patterns where agents modify, delete, or suppress log entries:
- log_deletion: removing or purging log files or entries
- log_modification: altering existing log content
- timestamp_manipulation: changing timestamps to hide activity timing
- log_suppression: preventing log generation or forwarding
- audit_trail_evasion: circumventing audit logging mechanisms
- log_injection: injecting false entries to obscure real activity
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "log_deletion": {
        "patterns": [
            r"(?i)(delet|remov|purg|clear|wipe|erase|destroy)\w*\s+(log|audit|trace|record|journal|syslog)",
            r"(?i)(log|audit|trace|record|journal)\s+(delet|remov|purg|clear|wipe|erase|destroy)",
            r"(?i)(truncat|shred|overwrite)\w*\s+(log|audit)\s*(file|entr|record|data)",
            r"(?i)rm\s+(-rf?\s+)?(/var/log|.*\.log|.*audit)",
        ],
        "severity": "critical",
        "description": "Removing or purging log files or entries to destroy evidence",
    },
    "log_modification": {
        "patterns": [
            r"(?i)(modif|alter|edit|chang|tamper|manipulat)\w*\s+(log|audit|trace|record|journal)\s*(file|entr|record|data|content)?",
            r"(?i)(log|audit|trace|record)\s+(modif|alter|edit|chang|tamper|manipulat)",
            r"(?i)(rewrite|falsif|forg)\w*\s+(log|audit|record|entr)",
            r"(?i)(sed|awk)\s+.*\s+(log|audit|syslog)",
        ],
        "severity": "critical",
        "description": "Altering existing log content to hide or misrepresent activity",
    },
    "timestamp_manipulation": {
        "patterns": [
            r"(?i)(manipulat|alter|chang|modif|forg|falsif)\w*\s+(timestamp|time.?stamp|date.?time|clock|time)",
            r"(?i)(timestamp|time.?stamp)\s+(manipulat|alter|chang|modif|forg|falsif|spoof|fake)",
            r"(?i)(backdat|predat|redat)\w*\s+(log|audit|record|entr|event)",
            r"(?i)(clock|time)\s+(skew|drift|offset|adjust)\w*\s+(to\s+)?(hide|conceal|mask|obscure)",
        ],
        "severity": "high",
        "description": "Changing timestamps to hide the true timing of activities",
    },
    "log_suppression": {
        "patterns": [
            r"(?i)(suppress|silence|mute|disable|block|prevent)\w*\s+(log|audit|trace|record|journal|alert|warning)",
            r"(?i)(log|audit|alert)\s+(suppress|silence|mute|disable|block|prevent)",
            r"(?i)(redirect|devnull|/dev/null|discard|drop)\w*\s+(log|audit|output|stderr|stdout)",
            r"(?i)(turn|switch)\w*\s+off\s+(log|audit|trace|monitor|record)",
        ],
        "severity": "high",
        "description": "Preventing log generation or forwarding to hide activity",
    },
    "audit_trail_evasion": {
        "patterns": [
            r"(?i)(evad|bypass|circumvent|avoid|escape)\w*\s+(audit|logging|monitor|track|surveillance)\s*(trail|system|mechanism|control)?",
            r"(?i)(audit|logging)\s+(trail|system|mechanism)\s+(evad|bypass|circumvent|avoid|escape|defeat)",
            r"(?i)(unlog|untrace|untrack|unmonitor)\w*\s+(action|activit|operation|event|command)",
            r"(?i)(blind.spot|gap|hole)\s+(in\s+)?(audit|logging|monitor|track)",
        ],
        "severity": "critical",
        "description": "Circumventing audit logging mechanisms to avoid detection",
    },
    "log_injection": {
        "patterns": [
            r"(?i)(inject|insert|plant|forge|fabricat)\w*\s+(false|fake|bogus|decoy|misleading)?\s*(log|audit|record|entr|event)",
            r"(?i)(log|audit)\s+(inject|insertion|poison|spoof|forge|fabricat)",
            r"(?i)(false|fake|bogus|decoy|misleading)\s+(log|audit|record|entr|event|alert)",
            r"(?i)(flood|spam|noise)\w*\s+(log|audit|record)\w*\s+(to\s+)?(obscure|hide|mask|bury)",
        ],
        "severity": "high",
        "description": "Injecting false log entries to obscure real malicious activity",
    },
}


@dataclass
class TamperEvent:
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
    events: list[TamperEvent] = field(default_factory=list)


@dataclass
class TamperChain:
    agent: str = ""
    steps: list[TamperEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class LogTamperingReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[TamperChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(log.delet|log.modif|timestamp.manipulat|"
    r"log.suppress|audit.evas|log.inject|"
    r"log.tamper|audit.bypass|log.purg|log.wipe)\b"
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


def _detect_chains(events: list[dict]) -> list[TamperChain]:
    agent_events: dict[str, list[TamperEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = TamperEvent(
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
            chains.append(TamperChain(
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


def analyze_log_tampering(events_or_dir: str | Path | list[dict]) -> LogTamperingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> LogTamperingReport:
    report = LogTamperingReport(total_events=len(events))
    cat_events: dict[str, list[TamperEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = TamperEvent(
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


def format_text(report: LogTamperingReport) -> str:
    lines = [
        "Log Tampering Analysis",
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


def format_json(report: LogTamperingReport) -> str:
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
