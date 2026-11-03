"""Identity spoofing detection for agent incident reconstruction.

Detects patterns where agents impersonate other agents or users:
- agent_impersonation: pretending to be a different agent or service
- credential_forgery: fabricating or altering authentication credentials
- session_hijack: taking over another agent's active session
- role_escalation: assuming unauthorized roles or permissions
- identity_cloning: duplicating another entity's identity attributes
- trust_exploitation: abusing trusted relationships between agents
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "agent_impersonation": {
        "patterns": [
            r"(?i)(agent|service|bot|process)\s+(impersonat|masquerad|pretend|pose|disguise|spoof)\w*",
            r"(?i)(impersonat|masquerad|spoof|pretend)\w*\s+(as\s+)?(agent|service|bot|another|different)",
            r"(?i)(fake|forged|spoofed|false)\s+(agent|identity|service)\s*(id|name|header|claim)",
            r"(?i)(claim|assert|present)\w*\s+(to\s+be|as)\s+(another|different|trusted|authorized)\s+(agent|service)",
        ],
        "severity": "critical",
        "description": "Pretending to be a different agent or service",
    },
    "credential_forgery": {
        "patterns": [
            r"(?i)(credential|token|certificate|key)\s+(forg|fake|fabricat|counterfeit|tamper|alter|manipulat)",
            r"(?i)(forg|fake|fabricat|counterfeit|tamper)\w*\s+(credential|token|certificate|auth|api.key|jwt)",
            r"(?i)(invalid|expired|revoked|stolen)\s+(credential|token|certificate|session)\s+(use|present|submit|accept)",
            r"(?i)(craft|construct|generate)\w*\s+(fake|forged|false|invalid)\s+(credential|token|certificate|jwt)",
        ],
        "severity": "critical",
        "description": "Fabricating or altering authentication credentials",
    },
    "session_hijack": {
        "patterns": [
            r"(?i)(session|connection|channel)\s+(hijack|takeover|steal|intercept|capture|seize)",
            r"(?i)(hijack|takeover|steal|intercept|seize)\w*\s+(session|connection|active\s+session|channel)",
            r"(?i)(session.fixation|cookie.theft|token.replay|man.in.the.middle)\w*\s*(detect|attempt|found)",
            r"(?i)(unauthorized|illegitimate)\s+(session|connection)\s+(takeover|access|use|reuse)",
        ],
        "severity": "critical",
        "description": "Taking over another agent's active session",
    },
    "role_escalation": {
        "patterns": [
            r"(?i)(role|privilege|permission|access)\s+(escalat|elevat|expand|promot|upgrade|inflat)",
            r"(?i)(escalat|elevat|expand|assum)\w*\s+(unauthorized|higher|admin|root|elevated)\s+(role|privilege|permission|access)",
            r"(?i)(unauthorized|illegitimate|unapproved)\s+(role|privilege|permission)\s+(assignment|change|escalat|grant)",
            r"(?i)(assum|claim|grant)\w*\s+(admin|root|super|elevated)\s+(role|privilege|permission|access)",
        ],
        "severity": "high",
        "description": "Assuming unauthorized roles or permissions",
    },
    "identity_cloning": {
        "patterns": [
            r"(?i)(identity|profile|persona)\s+(clon|duplicat|copy|replica|mirror|spoof)",
            r"(?i)(clon|duplicat|copy|replica|mirror)\w*\s+(identity|profile|persona|fingerprint|signature)",
            r"(?i)(duplicate|replicated|cloned|copied)\s+(agent|service|user)\s*(identity|profile|id|credentials)",
            r"(?i)(steal|harvest|extract)\w*\s+(identity|profile|persona)\s+(attribute|detail|information|data)",
        ],
        "severity": "high",
        "description": "Duplicating another entity's identity attributes",
    },
    "trust_exploitation": {
        "patterns": [
            r"(?i)(trust|trusted)\s+(exploit|abuse|misuse|manipulat|violat|betray|leverage)",
            r"(?i)(exploit|abuse|misuse|manipulat|violat)\w*\s+(trust|trusted)\s*(relationship|chain|delegation|path)",
            r"(?i)(trust.chain|trust.boundary|trust.delegation)\s+(exploit|abuse|bypass|violat|manipulat)",
            r"(?i)(abuse|exploit|misuse)\w*\s+(trusted|authorized)\s+(relationship|connection|access|channel)",
        ],
        "severity": "high",
        "description": "Abusing trusted relationships between agents",
    },
}


@dataclass
class SpoofingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    identity_ref: str = ""
    spoofing_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[SpoofingEvent] = field(default_factory=list)


@dataclass
class SpoofingChain:
    agent: str = ""
    steps: list[SpoofingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    spoofing_score: float = 0.0


@dataclass
class IdentitySpoofingReport:
    total_events: int = 0
    spoofing_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    spoofing_chains: list[SpoofingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(impersonat|masquerad|credential.forg|session.hijack|"
    r"token.replay|role.escalat|identity.clon|trust.exploit|"
    r"cookie.theft|session.fixation|man.in.the.middle)\b"
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


def _detect_chains(events: list[dict]) -> list[SpoofingChain]:
    agent_events: dict[str, list[SpoofingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = SpoofingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                identity_ref=str(ev.get("identity_ref", ev.get("identity", ""))),
                spoofing_type=str(ev.get("spoofing_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(SpoofingChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                spoofing_score=round(score, 2),
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


def analyze_identity_spoofing(events_or_dir: str | Path | list[dict]) -> IdentitySpoofingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> IdentitySpoofingReport:
    report = IdentitySpoofingReport(total_events=len(events))
    cat_events: dict[str, list[SpoofingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.spoofing_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = SpoofingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                identity_ref=str(ev.get("identity_ref", ev.get("identity", ""))),
                spoofing_type=str(ev.get("spoofing_type", "")),
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
    report.spoofing_chains = _detect_chains(events)
    return report


def format_text(report: IdentitySpoofingReport) -> str:
    lines = [
        "Identity Spoofing Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Spoofing events: {report.spoofing_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.spoofing_chains:
        lines.append("")
        lines.append("Spoofing chains:")
        for c in report.spoofing_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.spoofing_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: IdentitySpoofingReport) -> str:
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
    for chain in data.get("spoofing_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
