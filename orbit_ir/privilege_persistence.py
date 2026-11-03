"""Privilege persistence detection for agent incident reconstruction.

Detects patterns where agents maintain unauthorized elevated access:
- setuid_abuse: exploiting setuid/setgid binaries for persistent elevation
- capability_retention: retaining Linux capabilities after privilege drop
- namespace_escape: escaping container/namespace isolation for host access
- token_caching: caching authentication tokens beyond authorized lifetime
- role_persistence: maintaining elevated roles after authorization expires
- access_token_theft: stealing access tokens from other agents or services
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "setuid_abuse": {
        "patterns": [
            r"(?i)(setuid|setgid|suid|sgid)\s+(abuse|exploit|misuse|leverag|manipulat)",
            r"(?i)(exploit|abuse|misuse|leverag)\w*\s+(setuid|setgid|suid|sgid)\s+(binary|program|file|bit)",
            r"(?i)(chmod|chown)\s+[u+]*s\s+(to\s+)?(escalat|persist|maintain|retain)",
            r"(?i)(sticky.bit|special.permission)\s+(exploit|abuse|set|manipulat)",
        ],
        "severity": "critical",
        "description": "Exploiting setuid/setgid binaries for persistent privilege elevation",
    },
    "capability_retention": {
        "patterns": [
            r"(?i)(capabilit|cap_)\w*\s+(retain|persist|keep|preserv|cache|stor)",
            r"(?i)(retain|persist|keep|preserv)\w*\s+(capabilit|cap_|elevated|privilege)\w*\s+(after|beyond|past)",
            r"(?i)(ambient|inheritable|permitted)\s+(capabilit|cap)\w*\s+(retain|set|add|preserv)",
            r"(?i)(privilege|capabilit)\s+(not\s+)?(drop|relinquish|revok|surrender)\w*\s+(fail|skip|bypass)",
        ],
        "severity": "critical",
        "description": "Retaining Linux capabilities after privilege drop should have occurred",
    },
    "namespace_escape": {
        "patterns": [
            r"(?i)(namespace|container|sandbox|jail)\s+(escape|breakout|bypass|evasion|breach)",
            r"(?i)(escape|break\s*out|bypass|evad)\w*\s+(from\s+)?(namespace|container|sandbox|jail|isolation)",
            r"(?i)(host\s+access|host\s+mount|host\s+pid|host\s+net)\s+(from|via|through)\s+(container|namespace|sandbox)",
            r"(?i)(nsenter|unshare|pivot_root)\s+(to\s+)?(escape|access|reach|enter)\s+(host|parent)",
        ],
        "severity": "critical",
        "description": "Escaping container or namespace isolation to access host resources",
    },
    "token_caching": {
        "patterns": [
            r"(?i)(token|credential|secret)\s+(cach|stor|sav|persist|retain)\w*\s+(beyond|after|past|longer)",
            r"(?i)(cach|stor|sav|persist|retain)\w*\s+(auth|access|bearer|session|api)\s+(token|credential|key)",
            r"(?i)(token|credential)\s+(lifetime|expir|ttl|validity)\s+(extend|bypass|ignor|overrid)",
            r"(?i)(stale|expired|revoked)\s+(token|credential|key)\s+(reuse|replay|cache|retain)",
        ],
        "severity": "high",
        "description": "Caching authentication tokens beyond their authorized lifetime",
    },
    "role_persistence": {
        "patterns": [
            r"(?i)(role|privilege|permission|access)\s+(persist|maintain|retain|keep)\w*\s+(after|beyond|past|despite)",
            r"(?i)(maintain|retain|keep|persist)\w*\s+(elevated|admin|root|privileged)\s+(role|access|permission|status)",
            r"(?i)(role|permission|privilege)\s+(escalat|elevat)\w*\s+(persist|permanent|indefinit|retain)",
            r"(?i)(authorization|authz|rbac)\s+(expir|revok|remov)\w*\s+(bypass|ignor|circumvent|evad)",
        ],
        "severity": "high",
        "description": "Maintaining elevated roles after authorization has expired or been revoked",
    },
    "access_token_theft": {
        "patterns": [
            r"(?i)(steal|theft|exfiltrat|harvest|intercept)\w*\s+(access|auth|bearer|session|api)\s+(token|credential|key|secret)",
            r"(?i)(access|auth|bearer|session)\s+(token|credential|key)\s+(steal|theft|exfiltrat|harvest|intercept|capture)",
            r"(?i)(token|credential|key)\s+(from\s+)?(other|another|neighbor|peer|sibling)\s+(agent|service|process|container)",
            r"(?i)(sniff|eavesdrop|intercept|capture)\w*\s+(token|credential|auth|session)\s+(traffic|exchange|handshake)",
        ],
        "severity": "critical",
        "description": "Stealing access tokens from other agents or services",
    },
}


@dataclass
class PersistenceEvent:
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
    events: list[PersistenceEvent] = field(default_factory=list)


@dataclass
class PersistenceChain:
    agent: str = ""
    steps: list[PersistenceEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class PrivilegePersistenceReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[PersistenceChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(setuid.abuse|capability.retention|namespace.escape|"
    r"token.cach|role.persist|access.token.theft|"
    r"privilege.persist|container.breakout|credential.steal)\b"
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


def _detect_chains(events: list[dict]) -> list[PersistenceChain]:
    agent_events: dict[str, list[PersistenceEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = PersistenceEvent(
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
            chains.append(PersistenceChain(
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


def analyze_privilege_persistence(events_or_dir: str | Path | list[dict]) -> PrivilegePersistenceReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> PrivilegePersistenceReport:
    report = PrivilegePersistenceReport(total_events=len(events))
    cat_events: dict[str, list[PersistenceEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = PersistenceEvent(
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


def format_text(report: PrivilegePersistenceReport) -> str:
    lines = [
        "Privilege Persistence Analysis",
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


def format_json(report: PrivilegePersistenceReport) -> str:
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
