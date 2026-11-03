"""Input validation bypass detection for agent incident reconstruction.

Detects patterns where agents bypass input validation controls:
- type_coercion: manipulating data types to bypass validation
- encoding_abuse: using encoding tricks to evade input filters
- boundary_overflow: exceeding expected input boundaries
- format_string: exploiting format string vulnerabilities
- injection_vector: SQL/NoSQL/LDAP injection attempts
- schema_violation: violating expected data schema constraints
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "type_coercion": {
        "patterns": [
            r"(?i)(type|data.?type)\s+(coercion|confusion|juggl|mismatch|cast|conver)\w*\s+(bypass|evade|exploit|attack)",
            r"(?i)(coerce|juggle|cast|convert)\w*\s+(type|data.?type|input)\s+(to\s+)?(bypass|evade|circumvent)",
            r"(?i)(bypass|evade|exploit)\w*\s+(via|through|using)\s+(type|data.?type)\s+(coercion|confusion|juggl)",
            r"(?i)(unexpected|wrong|malicious)\s+(type|data.?type)\s+(passed|submitted|sent|injected)",
        ],
        "severity": "high",
        "description": "Manipulating data types to bypass validation checks",
    },
    "encoding_abuse": {
        "patterns": [
            r"(?i)(encoding|encode|charset|unicode)\s+(abuse|trick|evasion|bypass|exploit|manipulat)",
            r"(?i)(double|nested|recursive)\s+(encod|escap|decode)\w*\s+(bypass|evade|exploit|attack)",
            r"(?i)(url|base64|hex|unicode|utf)\s+(encod|decode)\w*\s+(evasion|bypass|trick|payload)",
            r"(?i)(homoglyph|punycode|unicode)\s+(attack|exploit|bypass|trick|confus)",
        ],
        "severity": "high",
        "description": "Using encoding tricks to evade input validation filters",
    },
    "boundary_overflow": {
        "patterns": [
            r"(?i)(boundary|buffer|input|field)\s+(overflow|overrun|exceed|underflow|wrap)",
            r"(?i)(overflow|overrun|exceed)\w*\s+(boundary|buffer|limit|length|size|max|min)",
            r"(?i)(integer|numeric|size)\s+(overflow|underflow|wraparound|truncat)",
            r"(?i)(exceed|violat|breach)\w*\s+(max|min|limit|length|size|range|bound)\w*\s+(constraint|check|valid)",
        ],
        "severity": "critical",
        "description": "Exceeding expected input boundaries to trigger overflow conditions",
    },
    "format_string": {
        "patterns": [
            r"(?i)(format\s+string)\s+(attack|exploit|vulnerab|inject|manipulat|abuse)",
            r"(?i)(inject|exploit|abuse)\w*\s+(format\s+string|printf|sprintf|template)",
            r"(?i)(template|format)\s+(injection|exploit|attack|manipulat|abuse)",
            r"(?i)(string\s+format|template\s+literal)\s+(vulnerab|exploit|attack|inject)",
        ],
        "severity": "critical",
        "description": "Exploiting format string or template vulnerabilities in input processing",
    },
    "injection_vector": {
        "patterns": [
            r"(?i)(sql|nosql|ldap|xpath|xss|xml)\s+(injection|inject)\w*\s+(attempt|attack|detect|payload)",
            r"(?i)(injection|inject)\w*\s+(attempt|attack|vector|payload|detect)\w*\s+(via|through|in)\s+(input|param|field|query)",
            r"(?i)(malicious|crafted|adversarial)\s+(input|payload|query|parameter)\s+(inject|attempt|submit|send)",
            r"(?i)(input|param|field)\s+(sanitiz|valid|filter)\w*\s+(bypass|evasion|circumvent|fail)",
        ],
        "severity": "critical",
        "description": "SQL/NoSQL/LDAP/XSS injection attempts through input fields",
    },
    "schema_violation": {
        "patterns": [
            r"(?i)(schema|struct|format)\s+(violation|mismatch|breach|deviat|non.conform|invalid)",
            r"(?i)(violat|breach|deviat)\w*\s+(schema|struct|data.?model|contract|spec)\w*\s+(constraint|rule|valid)",
            r"(?i)(invalid|malformed|unexpected)\s+(schema|struct|payload|body|format)\s+(submitted|sent|received|detect)",
            r"(?i)(data|input)\s+(contract|schema|format)\s+(violation|breach|mismatch|invalid)",
        ],
        "severity": "high",
        "description": "Violating expected data schema or structural constraints",
    },
}


@dataclass
class ValidationEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_field: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategoryCount:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ValidationEvent] = field(default_factory=list)


@dataclass
class ValidationChain:
    agent: str = ""
    steps: list[ValidationEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class ValidationBypassReport:
    total_events: int = 0
    bypass_events: int = 0
    categories: list[CategoryCount] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    bypass_chains: list[ValidationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(type.coercion|encoding.abuse|buffer.overflow|"
    r"format.string|sql.injection|xss|schema.violat|"
    r"input.valid|injection|template.inject)\b"
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


def _detect_chains(events: list[dict]) -> list[ValidationChain]:
    agent_events: dict[str, list[ValidationEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = ValidationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_field=str(ev.get("target_field", ev.get("field", ""))),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ValidationChain(
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


def analyze_input_validation_bypass(events_or_dir: str | Path | list[dict]) -> ValidationBypassReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ValidationBypassReport:
    report = ValidationBypassReport(total_events=len(events))
    cat_events: dict[str, list[ValidationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.bypass_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ValidationEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_field=str(ev.get("target_field", ev.get("field", ""))),
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
    report.bypass_chains = _detect_chains(events)
    return report


def format_text(report: ValidationBypassReport) -> str:
    lines = [
        "Input Validation Bypass Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Bypass events: {report.bypass_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.bypass_chains:
        lines.append("")
        lines.append("Validation bypass chains:")
        for c in report.bypass_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.violation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ValidationBypassReport) -> str:
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
    for chain in data.get("bypass_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
