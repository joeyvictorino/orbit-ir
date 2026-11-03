"""Token replay attack detection for agent incident reconstruction.

Detects patterns where agents capture and replay authentication tokens,
session identifiers, or API keys to gain unauthorized access:
- token_capture: intercepting or extracting authentication tokens from traffic
- session_hijack: taking over active sessions using captured session identifiers
- credential_replay: replaying captured credentials against different services
- token_forge: crafting or modifying tokens to bypass authentication
- bearer_theft: stealing OAuth/JWT bearer tokens from headers or storage
- refresh_abuse: abusing token refresh mechanisms to maintain persistent access
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "token_capture": {
        "patterns": [
            r"(?i)(intercept|captur|extract|sniff|dump)\w*\s+(auth\w*\s+)?(token|jwt|bearer|session.?id|api.?key|credential)\s*(from|in|within|out.?of)?\s*(traffic|header|request|response|cookie|storage)?",
            r"(?i)(auth\w*\s+)?(token|jwt|bearer|session.?id|api.?key)\s+(intercept|captur|extract|sniff|dump|harvest)\w*\s*(from|via|through)?\s*(traffic|header|request|network|memory)?",
            r"(?i)(man.?in.?the.?middle|mitm|traffic.?intercept)\w*\s+(to\s+)?(captur|extract|steal|obtain)\w*\s+(token|jwt|bearer|credential|session)",
            r"(?i)(extract|read|dump|harvest)\w*\s+(from\s+)?(authorization\s+header|cookie\s+jar|local.?storage|session.?storage|env\w*\s+var)",
        ],
        "severity": "critical",
        "description": "Intercepting or extracting authentication tokens from traffic or storage",
    },
    "session_hijack": {
        "patterns": [
            r"(?i)(hijack|take.?over|steal|seiz)\w*\s+(active\s+)?(session|connection|auth\w*\s+context)\s*(using|with|via|through)?\s*(captur|stolen|intercept)?\w*\s*(token|session.?id|cookie)?",
            r"(?i)(session\s+)?(hijack|take.?over|fixation)\s+(attack|technique|attempt)\s+(using|with|via|against)\s+(captur|stolen|replay|inject)\w*\s*(token|session.?id|cookie)?",
            r"(?i)(inject|set|plant|fix)\w*\s+(known|predetermined|chosen)\s+(session.?id|token|cookie)\s+(to|for|into)\s+(hijack|control|impersonat|access)",
            r"(?i)(impersonat|act\s+as|pose\s+as|masquerad)\w*\s+(using|with|via|through)\s+(hijack|stolen|captur|replay)\w*\s*(session|token|credential|identity)",
        ],
        "severity": "critical",
        "description": "Taking over active sessions using captured session identifiers",
    },
    "credential_replay": {
        "patterns": [
            r"(?i)(replay|reuse|re.?send|re.?submit)\w*\s+(captur|stolen|intercept|previously.?used)\w*\s*(credential|token|password|auth\w*\s+data|session.?id)\s*(against|to|at|for)?\s*(different|another|multiple|other)?\s*(service|endpoint|api|system)?",
            r"(?i)(credential|token|auth\w*)\s+(replay|reuse)\s+(attack|technique|attempt)\s+(against|on|targeting|for)\s+(service|endpoint|api|system|target)",
            r"(?i)(pass.?the.?hash|pass.?the.?ticket|pass.?the.?token|credential.?stuff)\w*\s+(attack|technique|against|using|with)",
            r"(?i)(reuse|replay)\w*\s+(same|identical|previous)\s+(token|credential|session|auth\w*)\s+(across|between|on|at)\s+(multiple|different|various)\s+(service|endpoint|system|api)",
        ],
        "severity": "high",
        "description": "Replaying captured credentials against different services",
    },
    "token_forge": {
        "patterns": [
            r"(?i)(forg|craft|creat|generat|fabricat|manufactur)\w*\s+(fake|fraudulent|invalid|malicious|custom)\s*(auth\w*\s+)?(token|jwt|bearer|session.?id|credential|ticket)",
            r"(?i)(modif|alter|tamper|manipulat)\w*\s+(existing\s+)?(token|jwt|bearer|session.?id|claim)\s+(to|for)\s+(escalat|bypass|gain|impersonat|elevat)",
            r"(?i)(jwt|token)\s+(forg|craft|tamper|manipulat|none.?algorithm)\w*\s+(attack|technique|to|for|used)\s*(bypass|escalat|gain|access|impersonat)?",
            r"(?i)(sign|construct|assembl)\w*\s+(token|jwt|bearer)\s+(with|using)\s+(stolen|compromised|weak|known|guessable)\s+(key|secret|signing|algorithm)",
        ],
        "severity": "critical",
        "description": "Crafting or modifying tokens to bypass authentication",
    },
    "bearer_theft": {
        "patterns": [
            r"(?i)(steal|exfiltrat|extract|harvest|collect)\w*\s+(oauth|jwt|bearer|access|refresh)\s+(token|credential)\s*(from|in|out.?of|within)?\s*(header|storage|cookie|memory|log|cache)?",
            r"(?i)(oauth|jwt|bearer|access)\s+(token\s+)?(theft|steal|exfiltrat|harvest|leak)\w*\s*(from|via|through|in)?\s*(header|storage|xss|log|api|redirect)?",
            r"(?i)(authorization:\s*bearer|access.?token)\s+(leak|expos|log|dump|captur|steal|harvest)\w*\s*(to|in|via|through)?\s*(log|console|error|response|redirect)?",
            r"(?i)(redirect|open.?redirect|xss|cross.?site)\w*\s+(to\s+)?(steal|exfiltrat|captur|harvest)\w*\s+(oauth|bearer|access|refresh)\s+(token|credential)",
        ],
        "severity": "high",
        "description": "Stealing OAuth/JWT bearer tokens from headers or storage",
    },
    "refresh_abuse": {
        "patterns": [
            r"(?i)(abuse|exploit|misus|leverag)\w*\s+(token\s+)?(refresh|renewal|rotation)\s+(mechanism|endpoint|flow|process)\s+(to|for)\s+(maintain|persist|extend|keep)\s+(access|session|auth\w*)",
            r"(?i)(refresh\s+token)\s+(abuse|exploit|theft|replay|reuse|hoard)\w*\s+(to|for|attack|technique|against)\s*(maintain|persist|extend|unlimited|permanent)?\s*(access|session|auth\w*)?",
            r"(?i)(stockpil|hoard|collect|accumulat)\w*\s+(refresh|renewal)\s+(token|credential)\s+(for|to)\s+(future|later|persistent|long.?term)\s+(access|use|attack|abuse)",
            r"(?i)(prevent|block|disabl)\w*\s+(token\s+)?(revoc|invalidat|rotati)\w*\s+(to\s+)?(maintain|keep|extend|persist)\w*\s+(unauthorized\s+)?(access|session)",
        ],
        "severity": "high",
        "description": "Abusing token refresh mechanisms to maintain persistent access",
    },
}


@dataclass
class TokenReplayEvent:
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
    events: list[TokenReplayEvent] = field(default_factory=list)


@dataclass
class TokenReplayChain:
    agent: str = ""
    steps: list[TokenReplayEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class TokenReplayReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[TokenReplayChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(mitm|session.?hijack|pass.?the.?hash|pass.?the.?ticket|"
    r"credential.?stuff|jwt.?forge|bearer.?theft|token.?replay|"
    r"refresh.?abuse|session.?fixation|cookie.?theft|xss.?token)\b"
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


def _detect_chains(events: list[dict]) -> list[TokenReplayChain]:
    agent_events: dict[str, list[TokenReplayEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = TokenReplayEvent(
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
            chains.append(TokenReplayChain(
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


def analyze_token_replay(events_or_dir: str | Path | list[dict]) -> TokenReplayReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> TokenReplayReport:
    report = TokenReplayReport(total_events=len(events))
    cat_events: dict[str, list[TokenReplayEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = TokenReplayEvent(
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


def format_text(report: TokenReplayReport) -> str:
    lines = [
        "Token Replay Attack Analysis",
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


def format_json(report: TokenReplayReport) -> str:
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
