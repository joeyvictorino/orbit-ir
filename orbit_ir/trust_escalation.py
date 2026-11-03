"""Trust boundary escalation detection for agent incident reconstruction.

Detects patterns where agents manipulate trust relationships:
- trust_impersonation: impersonating trusted entities or services
- token_forgery: forging or fabricating trust tokens and certificates
- zone_escalation: escalating from low-trust to high-trust zones
- verification_bypass: bypassing trust verification mechanisms
- delegation_abuse: abusing trust delegation chains
- certificate_manipulation: tampering with certificates or PKI
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "trust_impersonation": {
        "patterns": [
            r"(?i)(impersonat|spoof|masquerad|pretend)\w*\s+(trust|authori[zs]|authentic)\w*\s+(entit|service|node|agent|system)",
            r"(?i)(trust|authori[zs])\w*\s+(entit|service|agent)\s+(impersonat|spoof|masquerad|forg)",
            r"(?i)(pose|act)\w*\s+as\s+(trust|authori[zs]|authentic|privileg)\w*\s+(entit|service|agent|user)",
            r"(?i)(fake|false|counterfeit)\s+(identity|credential|certif)\s+(present|claim|assert|use)",
        ],
        "severity": "critical",
        "description": "Impersonating trusted entities or services to gain access",
    },
    "token_forgery": {
        "patterns": [
            r"(?i)(forg|fabricat|counterfeit|craft)\w*\s+(trust|auth|access|bearer|jwt|session)\s*(token|ticket|cookie|assertion)",
            r"(?i)(trust|auth|access|bearer|jwt)\s*(token|ticket|cookie)\s+(forg|fabricat|counterfeit|tamper|modif)",
            r"(?i)(mint|generat|creat)\w*\s+(unauthori[zs]|illeg|fake|invalid)\w*\s+(token|ticket|session|cookie)",
            r"(?i)(token|ticket|session)\s+(replay|reuse|clone|duplic)\w*\s+(attack|abuse|exploit)",
        ],
        "severity": "critical",
        "description": "Forging or fabricating trust tokens and certificates",
    },
    "zone_escalation": {
        "patterns": [
            r"(?i)(escalat|cross|travers|breach|violat)\w*\s+(trust|security)\s*(zone|boundar|domain|perimeter|tier)",
            r"(?i)(low|untruste|public)\s*(trust|security)?\s*(zone|tier|domain)?\s*(to|into|toward)\s*(high|trust|privat|internal|secure)",
            r"(?i)(trust|security)\s*(zone|boundar|tier)\s*(escalat|breach|violat|cross|hop)",
            r"(?i)(lateral|vertical)\s+(trust|zone|boundar)\s+(escalat|travers|movement|hop)",
        ],
        "severity": "high",
        "description": "Escalating from low-trust to high-trust zones",
    },
    "verification_bypass": {
        "patterns": [
            r"(?i)(bypass|circumvent|skip|evad|disabl)\w*\s+(trust|cert|tls|ssl|signature|mtls)\s*(verif|valid|check|enforce)",
            r"(?i)(trust|cert|signature)\s*(verif|valid|check)\s+(bypass|circumvent|skip|evad|disabl)",
            r"(?i)(disabl|turn.off|ignor|suppress)\w*\s+(cert|tls|ssl|trust|signature)\s*(verif|valid|check|pin)",
            r"(?i)(accept|allow|trust)\w*\s+(invalid|expired|self.sign|untrust|revok)\w*\s+(cert|token|cred)",
        ],
        "severity": "high",
        "description": "Bypassing trust verification mechanisms",
    },
    "delegation_abuse": {
        "patterns": [
            r"(?i)(abuse|exploit|misuse)\w*\s+(trust|access|role)\s*(delegat|chain|inherit|proxy|forward)",
            r"(?i)(trust|access|role)\s*(delegat|chain|inherit)\s+(abuse|exploit|misuse|escalat|extend|chain)",
            r"(?i)(chain|cascade|propagat)\w*\s+(trust|access|delegat|permiss)\s+(beyond|exceed|escal|widen)",
            r"(?i)(transitive|indirect)\s+(trust|access|delegat)\s+(exploit|abuse|attack|escalat)",
        ],
        "severity": "high",
        "description": "Abusing trust delegation chains to extend access",
    },
    "certificate_manipulation": {
        "patterns": [
            r"(?i)(tamper|modif|alter|forg|replac)\w*\s+(cert|certif|x509|pki|ca)\w*",
            r"(?i)(cert|certif|x509|ca)\s+(tamper|modif|alter|forg|fake|counterfeit|inject)",
            r"(?i)(rogue|unauthori[zs]|self.sign|fake)\s+(ca|cert|certif|root)\s*(author|certif|sign|issu)",
            r"(?i)(certif|ca|pki)\s*(pin|chain|valid)\s*(bypass|tamper|break|remov|disabl)",
        ],
        "severity": "critical",
        "description": "Tampering with certificates or PKI infrastructure",
    },
}


@dataclass
class EscalationEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    source_zone: str = ""
    target_zone: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[EscalationEvent] = field(default_factory=list)


@dataclass
class EscalationChain:
    agent: str = ""
    steps: list[EscalationEvent] = field(default_factory=list)
    categories_involved: list[str] = field(default_factory=list)
    zones_traversed: list[str] = field(default_factory=list)


@dataclass
class TrustEscalationReport:
    total_events: int = 0
    escalation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    escalation_chains: list[EscalationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(impersonat|trust.spoof|token.forg|zone.escalat|"
    r"verif.bypass|delegat.abuse|cert.tamper|cert.forg|"
    r"mtls.bypass|jwt.forg|session.replay|trust.chain|"
    r"ca.inject|pki.tamper|lateral.trust|transitive.trust)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower().replace(" ", "-") if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[EscalationChain]:
    agent_events: dict[str, list[EscalationEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ee = EscalationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                source_zone=str(ev.get("source_zone", ev.get("from_zone", ""))),
                target_zone=str(ev.get("target_zone", ev.get("to_zone", ""))),
                raw=ev,
            )
            agent_events[agent].append(ee)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            zones = sorted(set(
                z for se in sevents
                for z in [se.source_zone, se.target_zone] if z
            ))
            chains.append(EscalationChain(
                agent=agent,
                steps=sevents[:10],
                categories_involved=cats,
                zones_traversed=zones,
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


def analyze_trust_escalation(events_or_dir: str | Path | list[dict]) -> TrustEscalationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    events = _load_events(str(events_or_dir))
    return _analyze(events)


def _analyze(events: list[dict]) -> TrustEscalationReport:
    report = TrustEscalationReport(total_events=len(events))

    cat_events: dict[str, list[EscalationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.escalation_events += 1
        for cat, technique in matches:
            agent = str(ev.get("agent_id", ev.get("source", "")))
            agents_seen.add(agent)
            ee = EscalationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                source_zone=str(ev.get("source_zone", ev.get("from_zone", ""))),
                target_zone=str(ev.get("target_zone", ev.get("to_zone", ""))),
                raw=ev,
            )
            cat_events[cat].append(ee)

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
    report.escalation_chains = _detect_chains(events)

    return report


def format_text(report: TrustEscalationReport) -> str:
    lines = [
        "Trust Escalation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Escalation events: {report.escalation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.escalation_chains:
        lines.append("")
        lines.append("Escalation chains:")
        for c in report.escalation_chains[:10]:
            zones = f", zones: {', '.join(c.zones_traversed)}" if c.zones_traversed else ""
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, categories: {', '.join(c.categories_involved)}{zones}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: TrustEscalationReport) -> str:
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
    for chain in data.get("escalation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
