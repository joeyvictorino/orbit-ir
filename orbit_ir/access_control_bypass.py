"""Access control bypass detection for agent incident reconstruction.

Detects patterns where agents circumvent authorization mechanisms:
- auth_bypass: bypassing authentication checks entirely
- token_manipulation: forging, stealing, or replaying auth tokens
- session_fixation: hijacking or fixing session identifiers
- role_elevation: escalating privileges beyond authorized role
- acl_modification: tampering with access control lists or policies
- permission_abuse: exploiting granted permissions beyond intended scope
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "auth_bypass": {
        "patterns": [
            r"(?i)(bypass|circumvent|skip|evade|avoid)\w*\s+(auth|authenticat|login|credential|verification)\s*(check|mechanism|control|system)?",
            r"(?i)(auth|authenticat|login)\s+(bypass|circumvent|skip|evade|avoid|defeat)",
            r"(?i)(unauth|without.auth|no.auth)\w*\s+(access|entry|request|connection|login)",
            r"(?i)(default|hardcoded|backdoor)\s+(credential|password|token|key)\s+(used|exploit|abuse)",
        ],
        "severity": "critical",
        "description": "Bypassing authentication checks to gain unauthorized access",
    },
    "token_manipulation": {
        "patterns": [
            r"(?i)(forg|fake|counterfeit|fabricat|craft)\w*\s+(token|jwt|session.token|auth.token|bearer|api.key)",
            r"(?i)(token|jwt|bearer|api.key)\s+(forg|fake|manipulat|tamper|steal|intercept|replay)",
            r"(?i)(steal|intercept|capture|exfiltrat|harvest)\w*\s+(token|jwt|bearer|api.key|credential|cookie)",
            r"(?i)(replay|reuse)\w*\s+(token|jwt|session|credential|auth)\s*(attack)?",
        ],
        "severity": "critical",
        "description": "Forging, stealing, or replaying authentication tokens",
    },
    "session_fixation": {
        "patterns": [
            r"(?i)(session)\s+(fixat|hijack|steal|tak|spoof|clone|replay)",
            r"(?i)(hijack|steal|takeover|spoof|clone)\w*\s+(session|cookie|session.id)",
            r"(?i)(fix|set|inject|plant)\w*\s+(session.id|session.token|session.cookie)",
            r"(?i)(cross.site|csrf|xss)\s+(session|cookie|token)\s+(steal|hijack|fixat)",
        ],
        "severity": "high",
        "description": "Hijacking or fixing session identifiers to impersonate users",
    },
    "role_elevation": {
        "patterns": [
            r"(?i)(elevat|escalat|promot|upgrad)\w*\s+(role|privilege|permission|access.level|clearance)",
            r"(?i)(role|privilege|permission)\s+(elevat|escalat|promot|upgrad|boost|expand)",
            r"(?i)(admin|root|superuser|super.admin)\s+(role|access|privilege)\s+(gain|obtain|acquire|assum|claim)",
            r"(?i)(unauthorized|illicit|illegitimate)\s+(role|privilege|permission)\s+(change|grant|assign|escalat)",
        ],
        "severity": "critical",
        "description": "Escalating privileges beyond the authorized role",
    },
    "acl_modification": {
        "patterns": [
            r"(?i)(modif|alter|chang|tamper|edit)\w*\s+(acl|access.control|permission.list|access.list|authorization.rule)",
            r"(?i)(acl|access.control|permission)\s+(modif|alter|chang|tamper|overwrit|bypass)",
            r"(?i)(add|grant|assign)\w*\s+(unauthorized|illicit|excess)\s+(permission|access|role|privilege)",
            r"(?i)(weaken|relax|loosen|disable)\w*\s+(acl|access.control|permission|authorization)\s*(rule|polic|check)?",
        ],
        "severity": "high",
        "description": "Tampering with access control lists or authorization policies",
    },
    "permission_abuse": {
        "patterns": [
            r"(?i)(abuse|misuse|exploit|leverage)\w*\s+(permission|privilege|access|grant|entitlement|capability)",
            r"(?i)(permission|privilege|access)\s+(abuse|misuse|exploit|overuse|overreach)",
            r"(?i)(exceed|overstep|go.beyond)\w*\s+(authorized|granted|allowed|permitted)\s+(scope|access|permission|action)",
            r"(?i)(lateral|horizontal)\s+(movement|access|traversal)\s+(via|through|using)\s+(permission|privilege|access)",
        ],
        "severity": "high",
        "description": "Exploiting granted permissions beyond their intended scope",
    },
}


@dataclass
class BypassEvent:
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
    events: list[BypassEvent] = field(default_factory=list)


@dataclass
class BypassChain:
    agent: str = ""
    steps: list[BypassEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class AccessControlBypassReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[BypassChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(auth.bypass|token.manipulat|session.fixat|"
    r"role.elevat|acl.modif|permission.abuse|"
    r"privilege.escalat|session.hijack|token.forg)\b"
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


def _detect_chains(events: list[dict]) -> list[BypassChain]:
    agent_events: dict[str, list[BypassEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = BypassEvent(
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
            chains.append(BypassChain(
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


def analyze_access_control_bypass(events_or_dir: str | Path | list[dict]) -> AccessControlBypassReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> AccessControlBypassReport:
    report = AccessControlBypassReport(total_events=len(events))
    cat_events: dict[str, list[BypassEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = BypassEvent(
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


def format_text(report: AccessControlBypassReport) -> str:
    lines = [
        "Access Control Bypass Analysis",
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


def format_json(report: AccessControlBypassReport) -> str:
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
