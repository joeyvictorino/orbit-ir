"""Data exfiltration detection for agent incident reconstruction.

Detects patterns where agents attempt to extract sensitive data:
- steganographic_output: hiding data in seemingly normal output
- encoding_abuse: using encoding tricks to smuggle data out
- channel_manipulation: abusing legitimate channels for exfiltration
- data_staging: staging data in intermediate locations before extraction
- metadata_leaking: embedding sensitive info in metadata fields
- gradual_extraction: slowly extracting data in small increments
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "steganographic_output": {
        "patterns": [
            r"(?i)(steganograph|stego|hidden.?data|embed.?data)\w*\s+(in|within|inside|through)\s+(output|response|image|text|message)",
            r"(?i)(hide|conceal|embed|encode)\w*\s+(sensitive|secret|private|confidential)\s+(data|info|content)\s+(in|within|inside)\s+(output|response|normal)",
            r"(?i)(covert|hidden|invisible|stealth)\s+(data|channel|payload|encoding)\s+(in|within|embedded)",
            r"(?i)(output|response|message)\s+(contain|embed|hide|conceal)\w*\s+(hidden|covert|secret|steganograph)",
        ],
        "severity": "critical",
        "description": "Hiding data in seemingly normal output using steganographic techniques",
    },
    "encoding_abuse": {
        "patterns": [
            r"(?i)(base64|hex|url.?encod|rot13|unicode)\s+(encod|smuggl|exfiltrat|extract|abuse|trick)",
            r"(?i)(encod|obfuscat|transform)\w*\s+(sensitive|secret|private|confidential)\s+(data|info|content)\s+(using|via|through|with)",
            r"(?i)(abuse|misuse|exploit|trick)\w*\s+(encoding|encoder|charset|unicode|transform)",
            r"(?i)(encoding|charset|unicode)\s+(abuse|misuse|exploit|trick|bypass|circumvent)",
        ],
        "severity": "high",
        "description": "Using encoding tricks to smuggle sensitive data out",
    },
    "channel_manipulation": {
        "patterns": [
            r"(?i)(abuse|misuse|exploit|hijack)\w*\s+(legitimate|normal|authorized|approved)\s+(channel|endpoint|api|service)\s+(for|to)\s+(exfiltrat|extract|smuggl|leak)",
            r"(?i)(exfiltrat|extract|smuggl|leak)\w*\s+(data|info|content)\s+(via|through|over|using)\s+(legitimate|normal|authorized|dns|http|log)",
            r"(?i)(channel|endpoint|api)\s+(manipulation|abuse|misuse|hijack)\s+(for|to)\s+(data|exfiltrat)",
            r"(?i)(dns|http|log|error)\s+(tunnel|exfiltrat|channel|covert)\s+(for|to)?\s*(data|extract|smuggl|leak)",
        ],
        "severity": "critical",
        "description": "Abusing legitimate communication channels for data exfiltration",
    },
    "data_staging": {
        "patterns": [
            r"(?i)(stage|staging|stash|cache|buffer)\w*\s+(data|info|content|secret|credential)\s+(for|before|prior|pending)\s+(exfiltrat|extract|transfer|retriev)",
            r"(?i)(data|info|content)\s+(stag|stash|cache|buffer|collect|accumulat)\w*\s+(in|at|to)\s+(tempor|intermediat|staging|buffer)",
            r"(?i)(collect|gather|accumulat|aggregat)\w*\s+(sensitive|secret|private|confidential)\s+(data|info|content)\s+(in|at|to|before)",
            r"(?i)(temporary|intermediate|staging|buffer)\s+(storage|location|area|file)\s+(for|contain|hold)\w*\s+(exfiltrat|extract|sensitive|secret)",
        ],
        "severity": "high",
        "description": "Staging data in intermediate locations before extraction",
    },
    "metadata_leaking": {
        "patterns": [
            r"(?i)(leak|embed|hide|smuggl)\w*\s+(sensitive|secret|private|confidential)\s+(data|info|content)\s+(in|via|through)\s+(metadata|header|tag|attribute|field)",
            r"(?i)(metadata|header|tag|attribute)\s+(leak|embed|contain|hide|smuggl)\w*\s+(sensitive|secret|private|confidential)",
            r"(?i)(exfiltrat|extract|smuggl|leak)\w*\s+(data|info|content)\s+(via|through|in)\s+(metadata|header|tag|attribute|http.?header|response.?header)",
            r"(?i)(metadata|header|tag)\s+(exfiltrat|extract|channel|abuse|manipulation)\s+(for|to)?\s*(data|sensitive|secret)",
        ],
        "severity": "high",
        "description": "Embedding sensitive information in metadata fields for exfiltration",
    },
    "gradual_extraction": {
        "patterns": [
            r"(?i)(gradual|incremental|slow|progressive|piecemeal)\w*\s+(exfiltrat|extract|leak|transfer|smuggl)\w*\s+(data|info|content|secret)",
            r"(?i)(exfiltrat|extract|leak|smuggl)\w*\s+(data|info|content)\s+(gradually|incrementally|slowly|bit.by.bit|piece.by.piece)",
            r"(?i)(small|tiny|micro|fragment)\s+(amount|chunk|piece|part|portion)\s+(of\s+)?(data|info|content)\s+(exfiltrat|extract|leak|transfer)",
            r"(?i)(drip|trickle|low.and.slow|slow.exfil)\w*\s+(exfiltrat|extract|data|transfer)",
        ],
        "severity": "critical",
        "description": "Slowly extracting data in small increments to avoid detection",
    },
}


@dataclass
class ExfilEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    exfil_channel: str = ""
    exfil_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ExfilEvent] = field(default_factory=list)


@dataclass
class ExfilChain:
    agent: str = ""
    steps: list[ExfilEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    exfil_score: float = 0.0


@dataclass
class DataExfiltrationReport:
    total_events: int = 0
    exfil_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    exfil_chains: list[ExfilChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(steganograph|encoding.abuse|channel.manipulat|"
    r"data.staging|metadata.leak|gradual.extract|"
    r"covert.channel|dns.tunnel|slow.exfil)\b"
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


def _detect_chains(events: list[dict]) -> list[ExfilChain]:
    agent_events: dict[str, list[ExfilEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ee = ExfilEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                exfil_channel=str(ev.get("exfil_channel", ev.get("channel", ""))),
                exfil_type=str(ev.get("exfil_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ee)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ExfilChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                exfil_score=round(score, 2),
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


def analyze_data_exfiltration(events_or_dir: str | Path | list[dict]) -> DataExfiltrationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> DataExfiltrationReport:
    report = DataExfiltrationReport(total_events=len(events))
    cat_events: dict[str, list[ExfilEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.exfil_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ExfilEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                exfil_channel=str(ev.get("exfil_channel", ev.get("channel", ""))),
                exfil_type=str(ev.get("exfil_type", "")),
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
    report.exfil_chains = _detect_chains(events)
    return report


def format_text(report: DataExfiltrationReport) -> str:
    lines = [
        "Data Exfiltration Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Exfiltration events: {report.exfil_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.exfil_chains:
        lines.append("")
        lines.append("Exfiltration chains:")
        for c in report.exfil_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.exfil_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: DataExfiltrationReport) -> str:
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
    for chain in data.get("exfil_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
