"""Configuration drift detection for agent incident reconstruction.

Detects patterns where agents make unauthorized modifications to system
configurations, permissions, or policies:
- config_modification: agent modifying system or application configuration files
- permission_change: agent altering access permissions or ACLs
- policy_override: agent overriding security policies or guardrails
- secret_rotation: agent tampering with secrets, keys, or certificates
- feature_toggle: agent enabling/disabling features without authorization
- schema_alteration: agent modifying database schemas or data structures
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "config_modification": {
        "patterns": [
            r"(?i)(modif|alter|chang|edit|overwrit)\w*\s+(config|configuration|setting|parameter|option)\w*\s+(file|value|entry|without|unauthoriz)",
            r"(?i)(unauthoriz|unexpect|anomal|suspicious)\w*\s+(config|configuration|setting)\s+(change|modification|alteration|update)",
            r"(?i)(config|configuration|setting)\s+(file|value|entry)\s+(modif|alter|chang|overwrit|tamper)\w*\s+(by|from)\s+(agent|process|unknown)",
            r"(?i)(system|application|service)\s+(config|configuration)\s+(drift|deviat|diverge|tamper)\w*\s+(detect|found|observ)",
        ],
        "severity": "high",
        "description": "Agent modifying system or application configuration files",
    },
    "permission_change": {
        "patterns": [
            r"(?i)(modif|alter|chang|escalat)\w*\s+(permission|access|ACL|role|privilege)\w*\s+(without|unauthoriz|unexpected)",
            r"(?i)(unauthoriz|unexpect|anomal)\w*\s+(permission|access|ACL|role)\s+(change|modification|escalation|grant)",
            r"(?i)(chmod|chown|setfacl|icacls)\w*\s+(unauthoriz|suspicious|unexpected|anomal)",
            r"(?i)(permission|access|role|privilege)\s+(grant|revok|modif|escalat)\w*\s+(by|from)\s+(unauthoriz|unknown|suspicious|compromis)\w*\s+(agent|process|user)",
        ],
        "severity": "critical",
        "description": "Agent altering access permissions or ACLs",
    },
    "policy_override": {
        "patterns": [
            r"(?i)(overrid|bypass|disabl|circumvent|weaken)\w*\s+(security|safety|guardrail|compliance|enforce)\w*\s+(policy|rule|control|check|constraint)",
            r"(?i)(security|safety|guardrail|compliance)\s+(policy|rule|control)\s+(overrid|bypass|disabl|circumvent|weaken)\w*\s+(by|from|without)",
            r"(?i)(policy|rule|control)\s+(enforcement|check|validation)\s+(disabl|bypass|skip|overrid)\w*\s+(by|via|from)\s+(agent|process)",
            r"(?i)(unauthoriz|unexpect)\w*\s+(policy|rule|guardrail|constraint)\s+(overrid|relaxation|weakening|disabl)",
        ],
        "severity": "critical",
        "description": "Agent overriding security policies or guardrails",
    },
    "secret_rotation": {
        "patterns": [
            r"(?i)(tamper|modif|replac|rotat|overwrit)\w*\s+(secret|key|credential|certificate|token|password)\w*\s+(without|unauthoriz|unexpected|suspicious)",
            r"(?i)(unauthoriz|unexpect|anomal|suspicious)\w*\s+(secret|key|credential|certificate)\s+(rotation|change|replacement|modification)",
            r"(?i)(secret|key|credential|certificate|API.key)\s+(tamper|replac|overwrit|inject|plant)\w*\s+(by|from|via)\s+(agent|process|unknown|compromis)",
            r"(?i)(backdoor|rogue|malicious)\s+(key|credential|certificate|token)\s+(install|inject|plant|substitut)\w*",
        ],
        "severity": "critical",
        "description": "Agent tampering with secrets, keys, or certificates",
    },
    "feature_toggle": {
        "patterns": [
            r"(?i)(enabl|disabl|toggl|flip|switch)\w*\s+(feature|flag|toggle|capability|function)\w*\s+(without|unauthoriz|unexpected|suspicious)",
            r"(?i)(unauthoriz|unexpect|anomal)\w*\s+(feature|flag|toggle|capability)\s+(enabl|disabl|change|flip|activation)",
            r"(?i)(feature|flag|toggle)\s+(enabl|disabl|activat|deactivat)\w*\s+(by|from|via)\s+(agent|process|unknown|compromis)\w*\s+(without|no)\s+(approv|authoriz)",
            r"(?i)(debug|admin|test|hidden|internal)\s+(mode|feature|flag|function)\s+(enabl|activat|unlock)\w*\s+(unauthoriz|without|suspicious)",
        ],
        "severity": "high",
        "description": "Agent enabling or disabling features without authorization",
    },
    "schema_alteration": {
        "patterns": [
            r"(?i)(modif|alter|drop|truncat|add)\w*\s+(database|table|schema|column|index)\w*\s+(without|unauthoriz|unexpected|suspicious)",
            r"(?i)(unauthoriz|unexpect|anomal|suspicious)\w*\s+(schema|database|table)\s+(change|modification|alteration|migration|drop)",
            r"(?i)(DDL|ALTER.TABLE|DROP.TABLE|CREATE.TABLE)\w*\s+(detect|observ|execut)\w*\s+(by|from|via)\s+(agent|process|unknown|unauthoriz)",
            r"(?i)(schema|database|data.structure)\s+(drift|deviat|tamper|corrupt)\w*\s+(detect|found|observ|by)\s+(agent|process|unknown)",
        ],
        "severity": "high",
        "description": "Agent modifying database schemas or data structures",
    },
}


@dataclass
class DriftEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[DriftEvent] = field(default_factory=list)


@dataclass
class DriftChain:
    agent: str = ""
    steps: list[DriftEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class ConfigDriftReport:
    total_events: int = 0
    drift_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    drift_chains: list[DriftChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(config.tamper|config.drift|permission.escalat|acl.change|"
    r"policy.override|guardrail.bypass|secret.tamper|key.rotation|"
    r"credential.replace|feature.toggle|flag.flip|schema.alter|"
    r"ddl.inject|table.drop|chmod|chown|setfacl)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[DriftChain]:
    from collections import defaultdict

    agent_events: dict[str, list[DriftEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            de = DriftEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(de)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(DriftChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
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


def analyze_config_drift(events_or_dir: str | Path | list[dict]) -> ConfigDriftReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> ConfigDriftReport:
    report = ConfigDriftReport(total_events=len(events))

    cat_events: dict[str, list[DriftEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.drift_events += 1
        for cat, technique in matches:
            e = DriftEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if technique:
                techniques_seen.add(technique)

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

    report.techniques_seen = sorted(techniques_seen)
    report.drift_chains = _detect_chains(events)

    return report


def format_text(report: ConfigDriftReport) -> str:
    lines = [
        "Configuration Drift Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Drift events: {report.drift_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.techniques_seen:
        lines.append("")
        lines.append(f"Techniques seen: {', '.join(report.techniques_seen)}")

    if report.drift_chains:
        lines.append("")
        lines.append("Drift chains:")
        for c in report.drift_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ConfigDriftReport) -> str:
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
    for chain in data.get("drift_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
