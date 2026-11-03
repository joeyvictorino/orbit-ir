"""Dependency hijack detection for agent incident reconstruction.

Detects dependency confusion, hijack, and supply chain manipulation patterns:
- package_confusion: dependency confusion via namespace squatting or typosquatting
- registry_hijack: unauthorized registry takeover or poisoned package sources
- version_pinning_bypass: circumventing version pins to inject malicious versions
- build_injection: injecting malicious code during build or install processes
- transitive_poisoning: compromising transitive/indirect dependencies
- lockfile_tampering: manipulating lockfiles or manifest integrity checksums
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "package_confusion": {
        "patterns": [
            r"(?i)(package|dependency|module)\s+(confusion|squat|typosquat|impersonat)",
            r"(?i)(namespace|scope|registry)\s+(squat|hijack|confus|collisi|spoof)",
            r"(?i)(typosquat|name.?squat|combosquat)\w*\s+(package|module|dependency|library)",
            r"(?i)(internal|private)\s+(package|module)\s+(confus|overrid|shadow|replac)\w*\s+(public|external|upstream)",
        ],
        "severity": "critical",
        "description": "Dependency confusion via namespace squatting or typosquatting",
    },
    "registry_hijack": {
        "patterns": [
            r"(?i)(registry|repository|index)\s+(hijack|takeover|compromise|poison|spoof)",
            r"(?i)(malicious|rogue|compromis)\w*\s+(registry|repository|package\s+source|mirror)",
            r"(?i)(redirect|divert|mitm)\w*\s+(package|dependency|download)\s+(to|from|via)\s+(malicious|rogue|attacker)",
            r"(?i)(poison|corrupt|tamper)\w*\s+(package|artifact)\s+(registry|repository|source|mirror)",
        ],
        "severity": "critical",
        "description": "Unauthorized registry takeover or poisoned package sources",
    },
    "version_pinning_bypass": {
        "patterns": [
            r"(?i)(version|pin|lock)\w*\s+(bypass|circumvent|override|break|ignore)",
            r"(?i)(forc|inject|substitut)\w*\s+(version|release|tag)\s+(upgrad|downgrad|chang|replac)",
            r"(?i)(unpinn|float|wildcard|rang)\w*\s+(version|dependency|requirement)\s+(allow|enabl|inject|exploit)",
            r"(?i)(rollback|downgrad)\w*\s+(to|with)\s+(vulnerable|malicious|compromis|outdated)\s+(version|release|package)",
        ],
        "severity": "high",
        "description": "Circumventing version pins to inject malicious versions",
    },
    "build_injection": {
        "patterns": [
            r"(?i)(build|install|compile|setup)\s+(script|hook|phase|process)\s+(inject|tamper|modif|poison|backdoor)",
            r"(?i)(malicious|rogue|backdoor)\w*\s+(build|install|setup|post.?install|pre.?install)\s+(script|hook|command)",
            r"(?i)(inject|insert|embed)\w*\s+(code|payload|backdoor)\s+(during|in|via)\s+(build|install|compile|setup)",
            r"(?i)(setup\.py|setup\.cfg|pyproject|package\.json|Makefile)\s+(tamper|modif|inject|poison|backdoor)",
        ],
        "severity": "critical",
        "description": "Injecting malicious code during build or install processes",
    },
    "transitive_poisoning": {
        "patterns": [
            r"(?i)(transitive|indirect|nested|deep)\s+(dependency|package|module)\s+(poison|compromis|hijack|inject)",
            r"(?i)(compromis|poison|hijack)\w*\s+(transitive|indirect|sub.?dependency|nested)\s+(package|module|dependency)",
            r"(?i)(upstream|supply.?chain)\s+(dependency|package)\s+(compromis|inject|poison|tamper)",
            r"(?i)(diamond|chain|cascad)\w*\s+(dependency|package)\s+(attack|exploit|inject|conflict)",
        ],
        "severity": "high",
        "description": "Compromising transitive or indirect dependencies",
    },
    "lockfile_tampering": {
        "patterns": [
            r"(?i)(lockfile|lock.?file|manifest|checksum|hash)\s+(tamper|modif|alter|corrupt|forge|manipulat)",
            r"(?i)(alter|modif|forg|spoof)\w*\s+(integrity|checksum|hash|digest|signature)\s+(in|of|for)\s+(lockfile|manifest|package)",
            r"(?i)(bypass|circumvent|disable)\w*\s+(integrity|checksum|hash|verification|signature)\s+(check|validat)",
            r"(?i)(package|dependency)\s+(integrity|provenance|attestation)\s+(fail|violat|bypass|tamper|missing)",
        ],
        "severity": "high",
        "description": "Manipulating lockfiles or manifest integrity checksums",
    },
}


@dataclass
class HijackEvent:
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
    events: list[HijackEvent] = field(default_factory=list)


@dataclass
class HijackChain:
    agent: str = ""
    steps: list[HijackEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class DependencyHijackReport:
    total_events: int = 0
    hijack_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    hijack_chains: list[HijackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(typosquat|namespace.?squat|dependency.?confus|registry.?hijack|"
    r"version.?pin|build.?inject|transitive.?poison|lockfile.?tamper|"
    r"supply.?chain|package.?confus|checksum.?bypass|integrity.?violat)\b"
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


def _detect_chains(events: list[dict]) -> list[HijackChain]:
    agent_events: dict[str, list[HijackEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            he = HijackEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(he)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(HijackChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
            ))

    return chains[:20]


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


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


def analyze_dependency_hijack(events_or_dir: str | Path | list[dict]) -> DependencyHijackReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> DependencyHijackReport:
    report = DependencyHijackReport(total_events=len(events))

    cat_events: dict[str, list[HijackEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.hijack_events += 1
        for cat, technique in matches:
            e = HijackEvent(
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
    report.hijack_chains = _detect_chains(events)

    return report


def format_text(report: DependencyHijackReport) -> str:
    lines = [
        "Dependency Hijack Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Hijack events: {report.hijack_events}",
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

    if report.hijack_chains:
        lines.append("")
        lines.append("Hijack chains:")
        for c in report.hijack_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: DependencyHijackReport) -> str:
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
    for chain in data.get("hijack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
