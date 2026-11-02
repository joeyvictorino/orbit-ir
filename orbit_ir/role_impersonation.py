"""Role impersonation detection for agent incident reconstruction.

Detects patterns where agents claim identities or roles not assigned to them:
- identity_mismatch: agent_id in metadata differs from claimed identity
- credential_borrowing: agent uses another agent's credentials
- role_assumption: agent claims a role it was not assigned
- privilege_claim: agent claims admin/root privileges without authorization
- spoofed_header: forged identity headers (X-Agent-Id, X-Role, etc.)
- multi_identity: agent uses multiple identities across events
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "identity_mismatch": {
        "patterns": [
            r"(?i)(identity|agent.id|user.id)\s+(mismatch|differ|conflict|inconsisten)",
            r"(?i)(claimed|asserted|stated)\s+(identity|agent|user|role)\s+\w+\s+(differ|!=|does.not.match)",
            r"(?i)(actual|real|verified)\s+(identity|agent)\s*!=\s*(claimed|asserted|stated)",
            r"(?i)(impersonat|masquerad|pretend|pose.as)\w*\s+(agent|user|service|identity)",
        ],
        "severity": "critical",
        "description": "Agent identity in metadata differs from claimed identity",
    },
    "credential_borrowing": {
        "patterns": [
            r"(?i)(borrow|share|reuse|steal)\w*\S*\s+(credential|token|key|secret|cert)",
            r"(?i)(credential|token|key)\s+(borrow|share|reuse|steal)\w*",
            r"(?i)(credential|token|key)\s+(belong|assign|issu)\w*\s+(to\s+)?\w+\s+(used.by|from)\s+\w+",
            r"(?i)(cross.agent|foreign|other.agent)\s+(credential|token|key)",
            r"(?i)(unauthoriz|invalid)\w*\s+(credential|token)\s+(usage|access)",
        ],
        "severity": "critical",
        "description": "Agent uses credentials belonging to another agent",
    },
    "role_assumption": {
        "patterns": [
            r"(?i)(assum|claim|escalat|adopt)\w*\s+(\w+\s+)?(role|privilege|permission|authority)",
            r"(?i)role\s+(change|switch|escalat|modif)\w*\s+(unauthoriz|without|unapproved)",
            r"(?i)(unauthoriz|unapproved|unassigned)\s+(role|permission|access.level)",
            r"(?i)(act|operat|function)\w*\s+as\s+(admin|root|superuser|owner|manager)",
        ],
        "severity": "high",
        "description": "Agent claims a role it was not assigned",
    },
    "privilege_claim": {
        "patterns": [
            r"(?i)(claim|assert|request)\w*\s+(admin|root|sudo|superuser|elevated)\s*(access|privilege|permission|right)",
            r"(?i)(admin|root|superuser)\s+(privilege|access|right)\s+(claim|assert|grant)\w*\s+(unauthoriz|without.approval)",
            r"(?i)(false|fake|forg)\w*\s+(privilege|permission|authorization|admin)",
            r"(?i)(self.grant|auto.elevat|self.promot)\w*",
        ],
        "severity": "critical",
        "description": "Agent claims admin/root privileges without authorization",
    },
    "spoofed_header": {
        "patterns": [
            r"(?i)(spoof|forg|fake|tamper)\w*\s+(X-Agent|X-Role|X-Identity|X-User|X-Auth|From|Sender)",
            r"(?i)(X-Agent-Id|X-Role|X-Identity|X-User-Id)\s*:\s*\w+.*(?:spoof|forg|fake|modif|tamper)",
            r"(?i)(header|metadata)\s+(manipulation|tamper|injection|spoof|forg)",
            r"(?i)(inject|overrid|replac)\w*\s+(identity|role|agent)\s*(header|field|claim)",
        ],
        "severity": "high",
        "description": "Forged identity headers in requests",
    },
    "multi_identity": {
        "patterns": [
            r"(?i)(multiple|several|many|different)\s+(identit|persona|alias|name|id)\w*",
            r"(?i)(switch|alternate|rotat)\w*\s+(between\s+)?(identit|persona|alias|account)",
            r"(?i)(identity|persona)\s+(switch|hop|rotat|cycling)",
            r"(?i)agent\s+\w+\s+(also|simultaneously|alternately)\s+(known.as|identified.as|acting.as)",
        ],
        "severity": "high",
        "description": "Agent uses multiple identities across events",
    },
}


@dataclass
class ImpersonationEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    claimed_identity: str = ""
    actual_identity: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ImpersonationEvent] = field(default_factory=list)


@dataclass
class IdentityConflict:
    agent: str = ""
    identities_used: list[str] = field(default_factory=list)
    event_count: int = 0


@dataclass
class RoleImpersonationReport:
    total_events: int = 0
    impersonation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_impersonating: list[str] = field(default_factory=list)
    identity_conflicts: list[IdentityConflict] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_IDENTITY_FIELDS = ("agent_id", "claimed_agent", "actual_agent", "source", "user_id", "claimed_role", "actual_role")


def _classify_event(event: dict) -> list[tuple[str, str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                claimed = str(event.get("claimed_agent", event.get("claimed_role", "")))
                actual = str(event.get("actual_agent", event.get("agent_id", event.get("source", ""))))
                matches.append((cat, claimed, actual))
                break
    return matches


def _detect_identity_conflicts(events: list[dict]) -> list[IdentityConflict]:
    agent_identities: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        if not agent:
            continue
        agent_identities[agent].add(agent)
        for fld in ("claimed_agent", "claimed_role", "claimed_identity", "acting_as"):
            val = ev.get(fld)
            if val and str(val) != agent:
                agent_identities[agent].add(str(val))

    conflicts = []
    for agent, ids in sorted(agent_identities.items()):
        if len(ids) > 1:
            conflicts.append(IdentityConflict(
                agent=agent,
                identities_used=sorted(ids),
                event_count=sum(1 for ev in events if str(ev.get("agent_id", ev.get("source", ""))) == agent),
            ))

    return conflicts[:20]


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


def analyze_role_impersonation(events_or_dir: str | Path | list[dict]) -> RoleImpersonationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> RoleImpersonationReport:
    report = RoleImpersonationReport(total_events=len(events))

    cat_events: dict[str, list[ImpersonationEvent]] = {c: [] for c in CATEGORIES}
    impersonators: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.impersonation_events += 1
        for cat, claimed, actual in matches:
            source = str(ev.get("source", ev.get("agent_id", "")))
            e = ImpersonationEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=source,
                category=cat,
                claimed_identity=claimed,
                actual_identity=actual,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if source:
                impersonators.add(source)

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

    report.agents_impersonating = sorted(impersonators)
    report.identity_conflicts = _detect_identity_conflicts(events)

    return report


def format_text(report: RoleImpersonationReport) -> str:
    lines = [
        "Role Impersonation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Impersonation events: {report.impersonation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.agents_impersonating:
        lines.append("")
        lines.append(f"Agents impersonating: {', '.join(report.agents_impersonating)}")

    if report.identity_conflicts:
        lines.append("")
        lines.append("Identity conflicts:")
        for c in report.identity_conflicts[:10]:
            lines.append(f"  Agent {c.agent}: used {len(c.identities_used)} identities: {', '.join(c.identities_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: RoleImpersonationReport) -> str:
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
    return json.dumps(data, indent=2, default=str)
