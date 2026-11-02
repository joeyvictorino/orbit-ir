"""Environment variable manipulation detection for agent incident reconstruction.

Detects patterns of environment variable tampering, injection, and abuse:
- env_override: unauthorized override of critical environment variables
- env_injection: injection of malicious values into environment variables
- path_hijack: PATH variable manipulation for binary hijacking
- credential_swap: replacement of legitimate credentials with attacker-controlled ones
- config_poison: poisoning of configuration through environment variables
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


CATEGORIES = {
    "env_override": {
        "patterns": [
            r"(?i)env\s+(set|override|replace|modify|change)",
            r"(?i)(HOME|USER|SHELL|LANG)\s*=",
            r"(?i)unset\s+(HOME|USER|SHELL|PATH|LD_)",
            r"(?i)export\s+(HOME|USER|SHELL)=",
            r"(?i)overrid(e|ing)\s+(environment|env)\s+var",
        ],
        "severity": "high",
        "description": "Unauthorized override of critical environment variables",
    },
    "env_injection": {
        "patterns": [
            r"(?i)inject(ed|ing)?\s+(into\s+)?env",
            r"(?i)env\s+inject",
            r"(?i)\$\{.*:-.*\}",  # default value expansion abuse
            r'(?i)=.*\$\(.*\)',   # command substitution in value
            r"(?i)=.*`[^`]+`",    # backtick execution in value
        ],
        "severity": "critical",
        "description": "Injection of malicious values into environment variables",
    },
    "path_hijack": {
        "patterns": [
            r"(?i)PATH\s*=\s*/tmp",
            r"(?i)PATH\s*=\s*\.",
            r"(?i)PATH\s*=.*:/tmp",
            r"(?i)LD_PRELOAD\s*=",
            r"(?i)LD_LIBRARY_PATH\s*=\s*/tmp",
            r"(?i)PYTHONPATH\s*=\s*/tmp",
        ],
        "severity": "critical",
        "description": "PATH variable manipulation for binary hijacking",
    },
    "credential_swap": {
        "patterns": [
            r"(?i)(API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*\S+",
            r"(?i)(AWS_ACCESS|AWS_SECRET|AZURE_CLIENT)\s*=",
            r"(?i)DATABASE_URL\s*=",
            r"(?i)(replace|swap|change)\w*\s+(credential|token|key|secret)",
            r"(?i)credential\s+(swap|replace|override)",
        ],
        "severity": "critical",
        "description": "Replacement of credentials with attacker-controlled values",
    },
    "config_poison": {
        "patterns": [
            r"(?i)(CONFIG|CONF|CFG|SETTINGS)\s*=\s*/tmp",
            r"(?i)(NODE_ENV|FLASK_ENV|RAILS_ENV)\s*=\s*(development|test)",
            r"(?i)DEBUG\s*=\s*(true|1|yes)",
            r"(?i)(LOG_LEVEL|LOGLEVEL)\s*=\s*(debug|trace)",
            r"(?i)DISABLE_(AUTH|SSL|TLS|VERIFY)\s*=\s*(true|1|yes)",
        ],
        "severity": "high",
        "description": "Poisoning configuration through environment variables",
    },
}


@dataclass
class EnvEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    variable: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[EnvEvent] = field(default_factory=list)


@dataclass
class EnvReport:
    total_events: int = 0
    manipulation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    top_variables: list[dict] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values()).lower()
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                var_match = re.search(r'([A-Z_]{2,})\s*=', " ".join(str(v) for v in event.values()))
                variable = var_match.group(1) if var_match else ""
                matches.append((cat, variable))
                break
    return matches


def _load_events(evidence_dir: str) -> list[dict]:
    events = []
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


def analyze_env_manipulation(evidence_dir: str | Path) -> EnvReport:
    if isinstance(evidence_dir, Path):
        evidence_dir = str(evidence_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> EnvReport:
    report = EnvReport(total_events=len(events))

    cat_events: dict[str, list[EnvEvent]] = {c: [] for c in CATEGORIES}
    var_counts: dict[str, int] = {}

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.manipulation_events += 1
        for cat, variable in matches:
            e = EnvEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", "")),
                category=cat,
                variable=variable,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if variable:
                var_counts[variable] = var_counts.get(variable, 0) + 1

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

    sorted_vars = sorted(var_counts.items(), key=lambda x: -x[1])
    report.top_variables = [{"variable": v, "count": c} for v, c in sorted_vars[:10]]

    return report


def format_text(report: EnvReport) -> str:
    lines = [
        "Environment Variable Manipulation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Manipulation events: {report.manipulation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<20s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.top_variables:
        lines.append("")
        lines.append("Top targeted variables:")
        for v in report.top_variables[:5]:
            lines.append(f"  {v['variable']:<30s}  {v['count']} occurrences")

    lines.append("")
    return "\n".join(lines)


def format_json(report: EnvReport) -> str:
    def to_dict(obj):
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
