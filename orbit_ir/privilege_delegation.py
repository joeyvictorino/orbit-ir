"""Privilege delegation detection for agent incident reconstruction.

Detects patterns where agents delegate elevated privileges to sub-agents
or downstream processes without proper authorization or scope restrictions:
- unrestricted_delegation: delegating full admin/root privileges
- scope_escalation: sub-agent receiving broader scope than parent
- transitive_delegation: chain of delegations amplifying permissions
- implicit_delegation: privileges assumed via shared credentials
- delegation_without_audit: privilege hand-offs lacking audit trail
- revocation_gap: delegated privileges not revoked after task completion
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "unrestricted_delegation": {
        "patterns": [
            r"(?i)(delegat|grant|pass|assign|bestow)\w*\s+\w*\s*(admin|root|superuser|full|all)\s*(access|priv|perm|right|role)",
            r"(?i)(admin|root|superuser)\s+(delegat|grant|pass|assign|hand.off)\w*\s+to\s+\w*\s*(agent|sub.?agent|child|worker|downstream)",
            r"(?i)(wildcard|star|\*)\s*(perm|priv|access|role|scope)",
            r"(?i)grant\w*\s+all\s+(perm|priv|on|access)",
        ],
        "severity": "critical",
        "description": "Full admin/root privileges delegated to sub-agents",
    },
    "scope_escalation": {
        "patterns": [
            r"(?i)(sub.?agent|child|worker|downstream|callee)\s+(receiv|obtain|inherit|gain)\w*\s+\w*\s*(broader|wider|more|elevated|escalat)\w*\s*(scope|perm|priv|access)",
            r"(?i)(scope|perm|priv|access)\s+(broader|wider|expand|escalat|amplif)\w*\s+(than|beyond|exceed)\s+(parent|caller|origin)",
            r"(?i)(inherit|propagat|pass.through)\w*\s+(all|full|unrestrict)\w*\s*(perm|priv|scope|access|role)",
            r"(?i)(role|perm)\s+(creep|inflation|expansion)\b",
        ],
        "severity": "high",
        "description": "Sub-agent receiving broader scope than parent agent",
    },
    "transitive_delegation": {
        "patterns": [
            r"(?i)(chain|cascade|transitive|nested|recursive)\s+(delegat|grant|escalat|perm|priv)",
            r"(?i)(re.?delegat|sub.?delegat|further.delegat|onward.delegat)",
            r"(?i)(agent|process)\s+\w+\s+(delegat|grant)\w*\s+to\s+\w+\s+(which|who|that)\s+(then|further|also)\s+(delegat|grant)",
            r"(?i)(depth|level|hop)\s+(of|in)\s+(delegat|trust|perm)\s+chain",
        ],
        "severity": "high",
        "description": "Chain of delegations amplifying permissions",
    },
    "implicit_delegation": {
        "patterns": [
            r"(?i)(shared|common|reused)\s+(credential|secret|token|key|password)\s+(between|among|across)\s+\w*\s*(agent|process|service)",
            r"(?i)(inherit|assum|default)\w*\s+(perm|priv|role|credential)\s+(from|of|without)\s+(parent|environment|context|request)",
            r"(?i)(ambient|implicit|inferred|automatic)\s+(authority|perm|priv|credential|access)",
            r"(?i)(service.account|iam.role|execution.role)\s+(shared|reused|inherited|common)",
        ],
        "severity": "medium",
        "description": "Privileges assumed via shared credentials or inheritance",
    },
    "delegation_without_audit": {
        "patterns": [
            r"(?i)(delegat|grant|escalat)\w*\s+(without|no|missing|lack)\w*\s*(audit|log|trace|record|monitor)",
            r"(?i)(unlogged|untracked|unmonitored|silent)\s+(delegat|grant|escalat|perm|priv)",
            r"(?i)(audit|log|trace)\s+(miss|absent|gap|skip)\w*\s+(for|during|in)\s+(delegat|grant|escalat)",
            r"(?i)(no.record|no.trace|no.log|no.audit)\s+(of|for)\s+(delegat|grant|perm)",
        ],
        "severity": "medium",
        "description": "Privilege delegation without audit trail",
    },
    "revocation_gap": {
        "patterns": [
            r"(?i)(delegat|grant|temporary)\w*\s+(perm|priv|access|role)\s+(not|never|fail)\w*\s*(revok|remov|expir|withdrawn)",
            r"(?i)(stale|expired|orphan|leftover)\s+(delegat|grant|perm|priv|token|access)",
            r"(?i)(fail|miss|forget|skip)\w*\s+to\s+(revok|remov|clean|expir)\w*\s+(delegat|grant|perm|priv|access)",
            r"(?i)(ttl|expiry|timeout|lifetime)\s+(miss|absent|not.set|unbounded|infinite)\b",
        ],
        "severity": "high",
        "description": "Delegated privileges not revoked after task completion",
    },
}


@dataclass
class DelegationEvent:
    timestamp: str = ""
    source: str = ""
    target: str = ""
    category: str = ""
    privilege: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[DelegationEvent] = field(default_factory=list)


@dataclass
class DelegationChain:
    agents: list[str] = field(default_factory=list)
    privilege: str = ""
    depth: int = 0
    escalated: bool = False


@dataclass
class PrivilegeDelegationReport:
    total_events: int = 0
    delegation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    delegation_chains: list[DelegationChain] = field(default_factory=list)
    agents_with_delegations: list[str] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_AGENT_RE = re.compile(r"(?i)\b((?:agent|sub.?agent|worker|child|process|service|bot)\s*[\-_:]?\s*[A-Za-z0-9_-]+)")
_PRIV_RE = re.compile(r"(?i)\b(admin|root|write|read|execute|delete|create|full|superuser|owner|manager|operator|editor|viewer)\b")
_DELEGATE_RE = re.compile(r"(?i)\b(delegat|grant|assign|bestow|pass|hand.off|transfer|inherit|propagat)\w*")
_REVOKE_RE = re.compile(r"(?i)\b(revok|remov|withdraw|expir|rescind|reclaim|drop|clean.up)\w*")


def _classify_event(event: dict) -> list[tuple[str, str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                target_match = _AGENT_RE.search(text)
                target = target_match.group(1) if target_match else ""
                priv_match = _PRIV_RE.search(text)
                priv = priv_match.group(1).lower() if priv_match else ""
                matches.append((cat, target, priv))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[DelegationChain]:
    delegations: dict[str, list[str]] = {}

    for ev in events:
        text = " ".join(str(v) for v in ev.values())
        if not _DELEGATE_RE.search(text):
            continue

        source = str(ev.get("agent_id", ev.get("source", "")))
        agent_matches = _AGENT_RE.findall(text)
        target = ""
        for m in agent_matches:
            if m != source:
                target = m
                break
        if source and target:
            delegations.setdefault(source, []).append(target)

    chains: list[DelegationChain] = []
    for root, targets in delegations.items():
        chain = [root]
        current = targets
        depth = 1
        seen = {root}
        while current:
            next_level = []
            for t in current:
                if t not in seen:
                    chain.append(t)
                    seen.add(t)
                    if t in delegations:
                        next_level.extend(delegations[t])
            current = next_level
            depth += 1
            if depth > 5:
                break

        if len(chain) > 1:
            chains.append(DelegationChain(
                agents=chain[:10],
                depth=len(chain) - 1,
                escalated=len(chain) > 2,
            ))

    return chains[:10]


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


def analyze_privilege_delegation(events_or_dir: str | Path | list[dict]) -> PrivilegeDelegationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> PrivilegeDelegationReport:
    report = PrivilegeDelegationReport(total_events=len(events))

    cat_events: dict[str, list[DelegationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.delegation_events += 1
        source = str(ev.get("agent_id", ev.get("source", "")))
        for cat, target, priv in matches:
            e = DelegationEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=source,
                target=target,
                category=cat,
                privilege=priv,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if source:
                agents_seen.add(source)
            if target:
                agents_seen.add(target)

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

    report.delegation_chains = _detect_chains(events)
    report.agents_with_delegations = sorted(agents_seen)

    return report


def format_text(report: PrivilegeDelegationReport) -> str:
    lines = [
        "Privilege Delegation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Delegation events: {report.delegation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.delegation_chains:
        lines.append("")
        lines.append("Delegation chains:")
        for ch in report.delegation_chains[:5]:
            arrow = " -> ".join(ch.agents)
            esc = " [ESCALATED]" if ch.escalated else ""
            lines.append(f"  depth={ch.depth}: {arrow}{esc}")

    if report.agents_with_delegations:
        lines.append("")
        lines.append(f"Agents involved: {', '.join(report.agents_with_delegations[:20])}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: PrivilegeDelegationReport) -> str:
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
