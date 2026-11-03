"""Configuration tampering detection for agent incident reconstruction.

Detects patterns where agents modify system or application configurations maliciously:
- config_injection: injecting malicious values into configuration files
- env_manipulation: tampering with environment variables
- registry_tampering: modifying system registry or service registries
- settings_override: overriding security-critical application settings
- permission_change: modifying file or access permissions
- config_rollback_evasion: reverting configs to hide tampering evidence
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "config_injection": {
        "patterns": [
            r"(?i)(inject|insert|embed|plant)\w*\s+(into\s+)?(config|configuration|settings|\.conf|\.ini|\.yaml|\.yml)",
            r"(?i)(config|configuration|settings)\s+(inject|tamper|poison|corrupt|manipulat)",
            r"(?i)(malicious|unauthorized|rogue)\s+(config|configuration|setting|value|entry)\s+(inject|insert|add|write)",
            r"(?i)(append|prepend|overwrite)\w*\s+(malicious|unauthorized|hostile)\s+(config|entry|value|directive)",
        ],
        "severity": "critical",
        "description": "Injecting malicious values into configuration files or stores",
    },
    "env_manipulation": {
        "patterns": [
            r"(?i)(manipulat|tamper|modify|alter|change)\w*\s+(environment|env)\s*(variable|var|setting)",
            r"(?i)(environment|env)\s*(variable|var)\s+(manipulat|tamper|poison|hijack|override|spoof)",
            r"(?i)(set|export|unset|modify)\w*\s+(PATH|LD_PRELOAD|LD_LIBRARY_PATH|HOME|SHELL|USER)",
            r"(?i)(PATH|LD_PRELOAD|LD_LIBRARY)\s+(inject|hijack|manipulat|tamper|poison)",
        ],
        "severity": "critical",
        "description": "Tampering with environment variables to alter system behavior",
    },
    "registry_tampering": {
        "patterns": [
            r"(?i)(registry|service.registry|consul|etcd|zookeeper)\s+(tamper|modify|corrupt|poison|manipulat)",
            r"(?i)(tamper|modify|corrupt|poison)\w*\s+(with\s+)?(registry|service.registry|consul|etcd)",
            r"(?i)(unauthorized|illicit|rogue)\s+(registry|service)\s+(modification|change|update|write)",
            r"(?i)(registry|catalog|manifest)\s+(entry|key|value)\s+(tamper|corrupt|forge|spoof)",
        ],
        "severity": "high",
        "description": "Modifying system registries or service discovery registries",
    },
    "settings_override": {
        "patterns": [
            r"(?i)(override|bypass|disable|suppress)\w*\s+(security|safety|auth|access)\s*(setting|config|control|check)",
            r"(?i)(security|safety|auth)\s*(setting|config|control)\s+(override|bypass|disable|suppress|weaken)",
            r"(?i)(force|coerce|trick)\w*\s+(setting|config|option|flag)\s+(to|into)\s+(permissive|allow|disable|off|false)",
            r"(?i)(debug|test|dev)\s+(mode|flag|setting)\s+(enable|activate|force|inject)\w*\s+(in\s+)?(production|prod|live)",
        ],
        "severity": "critical",
        "description": "Overriding security-critical application settings",
    },
    "permission_change": {
        "patterns": [
            r"(?i)(chmod|chown|chgrp|setfacl|icacls)\s+(777|666|a\+rwx|world.writ)",
            r"(?i)(permission|privilege|access.control|acl)\s+(change|modify|weaken|relax|escalat|tamper)",
            r"(?i)(weaken|relax|broaden|open.up)\w*\s+(file|directory|folder|resource)\s+(permission|access|acl)",
            r"(?i)(unauthorized|illicit)\s+(permission|privilege|ownership)\s+(change|modification|escalation)",
        ],
        "severity": "high",
        "description": "Modifying file or access permissions to weaken security",
    },
    "config_rollback_evasion": {
        "patterns": [
            r"(?i)(rollback|revert|restore|undo)\w*\s+(config|configuration|setting)\s+(to\s+)?(hide|cover|mask|erase|conceal)",
            r"(?i)(hide|cover|conceal|erase|destroy)\w*\s+(config|configuration)\s+(change|modification|tampering|evidence)",
            r"(?i)(config|configuration)\s+(tampering|change)\s+(evidence|trace|log|record)\s+(destroy|erase|hide|remove)",
            r"(?i)(restore|revert)\w*\s+(original|previous|clean)\s+(config|configuration|setting)\s+(after|following)\s+(tamper|modif|change)",
        ],
        "severity": "high",
        "description": "Reverting configurations to hide evidence of tampering",
    },
}


@dataclass
class TamperingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    config_ref: str = ""
    tampering_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[TamperingEvent] = field(default_factory=list)


@dataclass
class TamperingChain:
    agent: str = ""
    steps: list[TamperingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    tampering_score: float = 0.0


@dataclass
class ConfigTamperingReport:
    total_events: int = 0
    tampering_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    tampering_chains: list[TamperingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(config.inject|env.manipulat|registry.tamper|settings.override|"
    r"permission.change|config.rollback|chmod|chown|LD_PRELOAD|PATH.hijack|"
    r"debug.mode|tamper.evidence)\b"
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


def _detect_chains(events: list[dict]) -> list[TamperingChain]:
    agent_events: dict[str, list[TamperingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            te = TamperingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                config_ref=str(ev.get("config_ref", ev.get("config", ""))),
                tampering_type=str(ev.get("tampering_type", "")),
                raw=ev,
            )
            agent_events[agent].append(te)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(TamperingChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                tampering_score=round(score, 2),
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


def analyze_config_tampering(events_or_dir: str | Path | list[dict]) -> ConfigTamperingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ConfigTamperingReport:
    report = ConfigTamperingReport(total_events=len(events))
    cat_events: dict[str, list[TamperingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.tampering_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = TamperingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                config_ref=str(ev.get("config_ref", ev.get("config", ""))),
                tampering_type=str(ev.get("tampering_type", "")),
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
    report.tampering_chains = _detect_chains(events)
    return report


def format_text(report: ConfigTamperingReport) -> str:
    lines = [
        "Configuration Tampering Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Tampering events: {report.tampering_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.tampering_chains:
        lines.append("")
        lines.append("Tampering chains:")
        for c in report.tampering_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.tampering_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ConfigTamperingReport) -> str:
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
    for chain in data.get("tampering_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
