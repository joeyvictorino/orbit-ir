"""Phishing and social engineering pattern detection for agent incident reconstruction.

Detects patterns where agents employ social engineering tactics:
- credential_harvesting: requesting passwords, tokens, API keys
- impersonation: pretending to be another entity or service
- urgency_manipulation: artificial urgency to bypass security checks
- link_manipulation: suspicious URL patterns, redirects, lookalike domains
- trust_exploitation: leveraging established trust to extract sensitive data
- pretexting: fabricated scenarios to justify access requests
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "credential_harvesting": {
        "patterns": [
            r"(?i)(request|ask|prompt|demand|collect)\w*\s+(for\s+)?(password|credential|token|api.?key|secret|auth)",
            r"(?i)(password|credential|token|api.?key|secret)\s+(request|harvest|collect|gather|phish|steal|extract)",
            r"(?i)(enter|provide|share|send|submit)\s+(your\s+)?(password|credential|token|api.?key|secret|login)",
            r"(?i)(credential|password|token)\s+(phish|theft|steal|exfiltrat|harvest|scrape)",
        ],
        "severity": "critical",
        "description": "Requesting or collecting passwords, tokens, API keys or other credentials",
    },
    "impersonation": {
        "patterns": [
            r"(?i)(impersonat|pretend|masquerad|pose\s+as|spoof|mimic)\w*\s+(as\s+)?(admin|service|system|user|authority|support)",
            r"(?i)(fake|forged|spoofed|fraudulent)\s+(identity|account|profile|certificate|badge)",
            r"(?i)(claim|assert|represent)\w*\s+(to\s+be|being)\s+(admin|root|system|authority|support|manager)",
            r"(?i)(identity|user|service)\s+(spoof|impersonat|forgery|fraud|fake)",
        ],
        "severity": "critical",
        "description": "Agent pretending to be another entity or service to gain trust",
    },
    "urgency_manipulation": {
        "patterns": [
            r"(?i)(urgent|immediate|emergency|critical|asap|time.sensitive)\s+(action|response|access|approval|request)",
            r"(?i)(act\s+now|act\s+immediately|respond\s+now|hurry|before\s+it.s\s+too\s+late)",
            r"(?i)(deadline|expir|timeout|window\s+clos)\w*\s+(soon|imminent|approach|today|minutes|hours)",
            r"(?i)(bypass|skip|override)\w*\s+(review|approval|check)\w*\s+(due\s+to\s+)?(urgency|emergency|time)",
        ],
        "severity": "high",
        "description": "Creating artificial urgency to bypass security checks",
    },
    "link_manipulation": {
        "patterns": [
            r"(?i)(suspicious|malicious|phishing|spoofed|fake)\s+(url|link|domain|redirect|site)",
            r"(?i)(click|visit|open|follow)\s+(this|the)\s+(link|url|site).*?(redirect|forward|shorten)",
            r"(?i)(lookalike|typosquat|homograph|punycode|similar)\s+(domain|url|site|link)",
            r"(?i)(url|link|domain)\s+(manipulat|spoof|redirect|hijack|forge|obfuscat)",
        ],
        "severity": "high",
        "description": "Suspicious URL patterns, redirects, or lookalike domains",
    },
    "trust_exploitation": {
        "patterns": [
            r"(?i)(exploit|abuse|leverage|misuse)\w*\s+(trust|relationship|authority|permission|access|rapport)",
            r"(?i)(trust|rapport|authority|relationship)\s+(exploit|abuse|misuse|leverage|weaponiz)",
            r"(?i)(established|existing|prior)\s+(trust|relationship|access)\s+(to\s+)?(extract|steal|obtain|access)",
            r"(?i)(social\s+engineer|manipulat)\w*\s+(trust|confidence|relationship|rapport)",
        ],
        "severity": "high",
        "description": "Leveraging established trust to extract sensitive data",
    },
    "pretexting": {
        "patterns": [
            r"(?i)(pretext|fabricat|invent|fake|false)\w*\s+(scenario|story|reason|justification|excuse|context)",
            r"(?i)(fabricat|invent|manufacture)\w*\s+(reason|story|pretext|justification)\s+(to|for)\s+(access|request|obtain)",
            r"(?i)(false|fake|fraudulent)\s+(pretense|pretext|claim|story|excuse)\s+(to|for)\s+(gain|obtain|request|access)",
            r"(?i)(social\s+engineering|confidence\s+trick|con\s+scheme|grift)\w*\s+(attempt|attack|tactic)",
        ],
        "severity": "high",
        "description": "Fabricated scenarios to justify access requests or data extraction",
    },
}


@dataclass
class PhishingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategoryCount:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[PhishingEvent] = field(default_factory=list)


@dataclass
class PhishingChain:
    agent: str = ""
    steps: list[PhishingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class PhishingReport:
    total_events: int = 0
    phishing_events: int = 0
    categories: list[CategoryCount] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    phishing_chains: list[PhishingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(credential.harvest|impersonat|urgency|phishing|"
    r"social.engineer|pretext|trust.exploit|link.manipulat|"
    r"spoof|masquerad|typosquat)\b"
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


def _detect_chains(events: list[dict]) -> list[PhishingChain]:
    agent_events: dict[str, list[PhishingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            pe = PhishingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(PhishingChain(
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


def analyze_phishing(events_or_dir: str | Path | list[dict]) -> PhishingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> PhishingReport:
    report = PhishingReport(total_events=len(events))
    cat_events: dict[str, list[PhishingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.phishing_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = PhishingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                raw=ev,
            )
            cat_events[cat].append(e)
            if agent:
                agents_seen.add(agent)

    for cat, info in CATEGORIES.items():
        evts = cat_events[cat]
        report.categories.append(CategoryCount(
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
    report.phishing_chains = _detect_chains(events)
    return report


def format_text(report: PhishingReport) -> str:
    lines = [
        "Phishing Detection Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Phishing events: {report.phishing_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.phishing_chains:
        lines.append("")
        lines.append("Phishing chains:")
        for c in report.phishing_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.violation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: PhishingReport) -> str:
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
    for chain in data.get("phishing_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
