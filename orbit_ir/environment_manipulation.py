"""Environment variable manipulation pattern detection for agent incident reconstruction.

Detects patterns where agents manipulate environment variables for attack purposes:
- path_hijacking: modifying PATH to execute malicious binaries
- ld_preload_injection: injecting shared libraries via LD_PRELOAD
- env_poisoning: poisoning environment variables to alter program behavior
- config_override: overriding configuration via environment variables
- credential_extraction: extracting secrets from environment variables
- env_persistence: persisting access through environment variable modification
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "path_hijacking": {
        "patterns": [
            r"(?i)(path|PATH)\s+(hijack|manipulat|poison|modif|tamper|inject|prepend|overrid)",
            r"(?i)(hijack|manipulat|poison|modif|tamper)\w*\s+(the\s+)?(PATH|path\s+variable|search\s+path|exec\w*\s+path)",
            r"(?i)(prepend|insert|inject)\w*\s+(malicious|untrusted|attacker)\w*\s+(director|path|binary|entry)",
            r"(?i)(malicious|rogue|trojan)\s+(binary|executable|script)\s+(in|via|through)\s+(PATH|path)",
        ],
        "severity": "critical",
        "description": "Modifying PATH to execute malicious binaries instead of legitimate ones",
    },
    "ld_preload_injection": {
        "patterns": [
            r"(?i)(LD_PRELOAD|ld_preload)\s+(inject|set|modif|manipulat|exploit|attack|abuse)",
            r"(?i)(inject|set|load|force)\w*\s+(LD_PRELOAD|shared\s+librar|\.so\s+file|dynamic\s+librar)",
            r"(?i)(LD_LIBRARY_PATH|ld_library_path|DYLD_INSERT_LIBRARIES)\s+(inject|modif|manipulat|hijack|poison)",
            r"(?i)(preload|library)\s+(injection|hijack|interpos|hook)\w*\s+(attack|exploit|attempt|detect)",
        ],
        "severity": "critical",
        "description": "Injecting shared libraries via LD_PRELOAD or similar mechanisms",
    },
    "env_poisoning": {
        "patterns": [
            r"(?i)(environment|env)\s+(variable|var)?\s*(poison|tamper|manipulat|corrupt|inject|pollut)",
            r"(?i)(poison|tamper|manipulat|corrupt|inject|pollut)\w*\s+(environment|env)\s+(variable|var|setting)",
            r"(?i)(set|export|modify|alter)\w*\s+(environment|env)\s+(variable|var)?\s*(to\s+)?(malicious|hostile|crafted|unexpected)",
            r"(?i)(env\s+var|environment\s+variable)\s+(overwrit|replac|substitut|spoof)\w*\s+(attack|exploit|malicious)",
        ],
        "severity": "high",
        "description": "Poisoning environment variables to alter program behavior",
    },
    "config_override": {
        "patterns": [
            r"(?i)(config|configuration)\s+(override|overwrite|bypass|manipulat|tamper)\w*\s+(via|through|using)\s+(env|environment)",
            r"(?i)(override|overwrite|bypass)\w*\s+(config|configuration|setting)\w*\s+(via|through|using)\s+(env|environment)",
            r"(?i)(env|environment)\s+(variable|var)?\s*(override|overwrite|bypass|force)\w*\s+(config|configuration|security|auth)",
            r"(?i)(HOME|USER|SHELL|EDITOR|TMPDIR|TMP|TEMP)\s+(manipulat|override|tamper|hijack|poison|modif)",
        ],
        "severity": "high",
        "description": "Overriding security configuration through environment variable manipulation",
    },
    "credential_extraction": {
        "patterns": [
            r"(?i)(extract|steal|exfiltrat|harvest|dump|read|leak)\w*\s+(credential|secret|token|key|password|api.key)\w*\s+(from\s+)?(env|environment)",
            r"(?i)(env|environment)\s+(variable|var)?\s*(credential|secret|token|key|password)\s+(extract|steal|exfiltrat|harvest|dump|leak)",
            r"(?i)(AWS_SECRET|API_KEY|DATABASE_URL|DB_PASSWORD|SECRET_KEY|AUTH_TOKEN)\s+(expos|extract|leak|steal|dump|read|access)",
            r"(?i)(scan|search|enumerate|list)\w*\s+(env|environment)\w*\s+(for\s+)?(credential|secret|token|key|password|sensitive)",
        ],
        "severity": "critical",
        "description": "Extracting secrets and credentials from environment variables",
    },
    "env_persistence": {
        "patterns": [
            r"(?i)(persist|maintain|establish)\w*\s+(access|backdoor|presence)\w*\s+(via|through|using)\s+(env|environment)",
            r"(?i)(modify|alter|edit)\w*\s+(\.bashrc|\.profile|\.bash_profile|\.zshrc|/etc/environment|/etc/profile)",
            r"(?i)(env|environment)\s+(variable|var)?\s*(persist|backdoor|implant|trojan)\w*\s+(access|entry|hook)",
            r"(?i)(startup|init|login|shell)\s+(script|file|config)\s+(modif|inject|tamper|poison)\w*\s+(env|environment|variable)",
        ],
        "severity": "high",
        "description": "Persisting access through environment variable or shell profile modification",
    },
}


@dataclass
class EnvManipulationEvent:
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
    events: list[EnvManipulationEvent] = field(default_factory=list)


@dataclass
class EnvManipulationChain:
    agent: str = ""
    steps: list[EnvManipulationEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class EnvManipulationReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[EnvManipulationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(path.hijack|ld.preload|env.poison|config.override|"
    r"credential.extract|env.persist|library.inject|"
    r"shell.profile|bashrc.inject|environment.tamper)\b"
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


def _detect_chains(events: list[dict]) -> list[EnvManipulationChain]:
    agent_events: dict[str, list[EnvManipulationEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = EnvManipulationEvent(
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
            chains.append(EnvManipulationChain(
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


def analyze_environment_manipulation(events_or_dir: str | Path | list[dict]) -> EnvManipulationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> EnvManipulationReport:
    report = EnvManipulationReport(total_events=len(events))
    cat_events: dict[str, list[EnvManipulationEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = EnvManipulationEvent(
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


def format_text(report: EnvManipulationReport) -> str:
    lines = [
        "Environment Manipulation Analysis",
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


def format_json(report: EnvManipulationReport) -> str:
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
