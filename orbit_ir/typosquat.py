"""Typosquatting and dependency confusion detection for agent incident reconstruction.

Detects patterns where agents introduce or exploit typosquatted packages:
- package_misspell: installing packages with names similar to popular ones
- namespace_confusion: exploiting public/private package namespace overlap
- version_pinning_remove: removing or weakening version pins to allow malicious upgrades
- dependency_injection: injecting unexpected dependencies into build configs
- registry_spoof: redirecting package resolution to attacker-controlled registries
- install_script_abuse: exploiting pre/post-install scripts for arbitrary code execution
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "package_misspell": {
        "patterns": [
            r"(?i)(typosquat|typo.squat|package\s+misspell|misspelled\s+package|similar\s+name\s+package)",
            r"(?i)(install|require|import|depend)\w*\s+(fake|rogue|malicious|lookalike|copycat)\s+(package|module|library|dep)",
            r"(?i)(homoglyph|homograph|confusable)\s+(package|name|domain|char)",
            r"(?i)(pip\s+install|npm\s+install|gem\s+install|cargo\s+add)\s+\S*(typo|misspel|lookalike)",
        ],
        "severity": "critical",
        "description": "Installing packages with names similar to popular legitimate ones",
    },
    "namespace_confusion": {
        "patterns": [
            r"(?i)(namespace|scope)\s+(confusion|collision|hijack|squat|conflict)",
            r"(?i)(dependency\s+confusion|dep\s+confusion|package\s+confusion)",
            r"(?i)(public|external)\s+(package|registry)\s+(override|shadow|replace|mask)\w*\s+(private|internal)",
            r"(?i)(internal\s+package)\s+(name|namespace)\s+(clash|conflict|collid|overlap)\w*\s+(public|external|registry)",
        ],
        "severity": "critical",
        "description": "Exploiting public/private package namespace overlap",
    },
    "version_pinning_remove": {
        "patterns": [
            r"(?i)(remov|delet|strip|weaken|relax|loosen)\w*\s+(version\s+pin|pin|lock|constraint|bound)",
            r"(?i)(version|dependency)\s+(pin|lock|freeze|constraint)\s+(remov|delet|strip|weaken|bypass|disable)",
            r"(?i)(unpin|unlock|float)\w*\s+(version|dependency|dep|package)",
            r"(?i)(requirements\.txt|package-lock|yarn\.lock|Gemfile\.lock|Cargo\.lock)\s+(delet|remov|modif|tamper)",
        ],
        "severity": "high",
        "description": "Removing or weakening version pins to allow malicious upgrades",
    },
    "dependency_injection": {
        "patterns": [
            r"(?i)(inject|insert|add|sneak)\w*\s+(malicious|unexpected|unauthor|rogue|hidden)\s+(dependency|dep|package|require)",
            r"(?i)(dependency|dep|package)\s+(inject|tamper|poison|backdoor|trojan)",
            r"(?i)(build\s+config|setup\.py|package\.json|pom\.xml|build\.gradle)\s+(tamper|modif|inject|poison|backdoor)",
            r"(?i)(malicious|rogue|backdoor)\s+(dependency|dep)\s+(add|insert|inject|introduc)",
        ],
        "severity": "critical",
        "description": "Injecting unexpected dependencies into build configurations",
    },
    "registry_spoof": {
        "patterns": [
            r"(?i)(registry|repo(sitory)?)\s+(spoof|redirect|hijack|poison|mirror\s+attack)",
            r"(?i)(redirect|point|switch)\w*\s+(package|dep|dependency)\s+(resolution|download|fetch)\s+(to\s+)?(malicious|attacker|rogue|fake)",
            r"(?i)(npmrc|pypirc|pip\.conf|nuget\.config)\s+(tamper|modif|redirect|poison|overrid)",
            r"(?i)(custom|fake|rogue|malicious)\s+(registry|mirror|index|repository)\s+(url|endpoint|source)",
        ],
        "severity": "critical",
        "description": "Redirecting package resolution to attacker-controlled registries",
    },
    "install_script_abuse": {
        "patterns": [
            r"(?i)(pre.?install|post.?install|setup\.py|install\s+script)\s+(abus|exploit|malicious|backdoor|execut|run\s+arbitrary)",
            r"(?i)(arbitrary|malicious)\s+(code|command)\s+(execut|run)\w*\s+(during|in|via|through)\s+(install|setup|build)",
            r"(?i)(install\s+hook|lifecycle\s+script|build\s+script)\s+(abus|exploit|hijack|backdoor)",
            r"(?i)(os\.system|subprocess|exec|eval)\s+(in|during|from)\s+(setup\.py|install|postinstall)",
        ],
        "severity": "high",
        "description": "Exploiting pre/post-install scripts for arbitrary code execution",
    },
}


@dataclass
class TyposquatEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    package_name: str = ""
    registry: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[TyposquatEvent] = field(default_factory=list)


@dataclass
class TyposquatChain:
    agent: str = ""
    steps: list[TyposquatEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    squat_score: float = 0.0


@dataclass
class TyposquatReport:
    total_events: int = 0
    squat_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    squat_chains: list[TyposquatChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(typosquat|dependency.confusion|namespace.confusion|"
    r"version.pin|install.script|registry.spoof|"
    r"package.misspell|dep.inject|registry.redirect)\b"
)


def classify_event(event: dict) -> dict:
    text = " ".join(str(v) for v in event.values())
    best_cat = ""
    best_confidence = 0.0
    indicators: list[str] = []

    for cat in CATEGORIES:
        match_count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                match_count += 1
        if match_count > 0:
            confidence = min(1.0, match_count * 0.3)
            if confidence > best_confidence:
                best_confidence = confidence
                best_cat = cat
            if match_count > 0:
                indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = TyposquatReport(total_events=len(events))
    cat_events: dict[str, list[TyposquatEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.squat_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            te = TyposquatEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                package_name=str(ev.get("package", ev.get("package_name", ""))),
                registry=str(ev.get("registry", ev.get("source_registry", ""))),
                raw=ev,
            )
            cat_events[cat].append(te)
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

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * severity_weight.get(cs.severity, 0.3)

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
    report.squat_chains = detect_chains(events)

    return _report_to_dict(report)


def detect_chains(events: list[dict]) -> list[TyposquatChain]:
    agent_events: dict[str, list[TyposquatEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            te = TyposquatEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(te)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(TyposquatChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                squat_score=round(score, 2),
            ))
    return chains[:20]


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
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


def _report_to_dict(report: TyposquatReport) -> dict:
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
    for chain in data.get("squat_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Typosquatting & Dependency Confusion Analysis",
        "=" * 50,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Squat events: {analysis.get('squat_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("squat_chains", [])
    if chains:
        lines.append("")
        lines.append("Typosquat chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['squat_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
