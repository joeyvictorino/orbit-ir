"""Clipboard hijacking detection for agent incident reconstruction.

Detects patterns where agents perform clipboard hijacking attacks:
- clipboard_read_exfil: reading clipboard contents to exfiltrate sensitive data
- clipboard_replace_crypto: replacing cryptocurrency addresses in clipboard
- clipboard_inject_command: injecting malicious commands via clipboard paste
- clipboard_credential_steal: harvesting passwords/tokens from clipboard
- clipboard_monitor_persist: persistent clipboard monitoring/keylogging
- clipboard_social_engineer: clipboard manipulation for social engineering
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "clipboard_read_exfil": {
        "patterns": [
            r"(?i)(read|access|capture|copy|grab|dump)\w*\s+(clipboard|pasteboard|clip\s+board)\s+(content|data|text|buffer)",
            r"(?i)(clipboard|pasteboard)\s+(read|access|capture|exfil|extract|steal|harvest|scrape)\w*",
            r"(?i)(exfiltrat|steal|harvest|extract)\w*\s+(from\s+)?(clipboard|pasteboard)\s*(content|data|buffer)?",
            r"(?i)(clipboard|pasteboard)\s+(content|data|text|buffer)\s+(exfiltrat|steal|send|upload|transmit)\w*",
        ],
        "severity": "high",
        "description": "Reading clipboard contents to exfiltrate sensitive data",
    },
    "clipboard_replace_crypto": {
        "patterns": [
            r"(?i)(replac|swap|substitut|overwrit)\w*\s+(clipboard|pasteboard)\s+(crypto|bitcoin|wallet|address|btc|eth)",
            r"(?i)(crypto|bitcoin|wallet|btc|eth)\s+(address)\s+(replac|swap|hijack|substitut)\w*\s+(in\s+)?(clipboard|pasteboard)",
            r"(?i)(clipboard|pasteboard)\s+(crypto|bitcoin|wallet|address)\s+(replac|swap|hijack)\w*",
            r"(?i)(address\s+swap|crypto\s+swap)\w*\s+(clipboard|pasteboard|paste)",
        ],
        "severity": "critical",
        "description": "Replacing cryptocurrency addresses in clipboard",
    },
    "clipboard_inject_command": {
        "patterns": [
            r"(?i)(inject|insert|place|plant|write)\w*\s+(malicious\s+)?(command|script|payload|code)\s+(into|via|through)\s+(clipboard|pasteboard)",
            r"(?i)(clipboard|pasteboard)\s+(inject|insert|plant)\w*\s+(malicious\s+)?(command|script|payload|code)",
            r"(?i)(pastejack|paste\s+jack|copy.paste\s+attack)\w*",
            r"(?i)(malicious|dangerous|crafted)\s+(clipboard|paste|pasteboard)\s+(payload|command|content|inject)\w*",
        ],
        "severity": "critical",
        "description": "Injecting malicious commands via clipboard paste",
    },
    "clipboard_credential_steal": {
        "patterns": [
            r"(?i)(clipboard|pasteboard)\s+(password|credential|token|secret|api.key|auth)\s+(steal|harvest|capture|grab|exfil)\w*",
            r"(?i)(steal|harvest|capture|grab|exfil)\w*\s+(password|credential|token|secret)\s+(from\s+)?(clipboard|pasteboard)",
            r"(?i)(password|credential|token|secret|api.key)\s+(in|from|via)\s+(clipboard|pasteboard)\s+(steal|harvest|capture|exfil)\w*",
            r"(?i)(clipboard|pasteboard)\s+(harvest|steal|capture)\w*\s+(password|credential|token|secret|key)",
        ],
        "severity": "critical",
        "description": "Harvesting passwords/tokens from clipboard",
    },
    "clipboard_monitor_persist": {
        "patterns": [
            r"(?i)(monitor|watch|surveil|track|poll)\w*\s+(clipboard|pasteboard)\s+(persistent|continuous|ongoing|constant|background)",
            r"(?i)(persistent|continuous|ongoing|background)\s+(clipboard|pasteboard)\s+(monitor|watch|surveil|track|poll)\w*",
            r"(?i)(clipboard|pasteboard)\s+(monitor|watcher|logger|tracker|spy)\w*\s+(install|deploy|run|start|enabl)\w*",
            r"(?i)(install|deploy|run|start)\w*\s+(clipboard|pasteboard)\s+(monitor|watcher|logger|tracker|spy)\w*",
        ],
        "severity": "high",
        "description": "Persistent clipboard monitoring/keylogging",
    },
    "clipboard_social_engineer": {
        "patterns": [
            r"(?i)(clipboard|pasteboard)\s+(manipulat|alter|modif|chang)\w*\s+(social\s+engineer|trick|deceiv|phish|lure)",
            r"(?i)(social\s+engineer|trick|deceiv|phish)\w*\s+(via|using|through)\s+(clipboard|pasteboard|paste)\s*(manipulat|alter|swap)?\w*",
            r"(?i)(manipulat|alter|modif)\w*\s+(clipboard|pasteboard|paste\s+content)\s+(to\s+)?(trick|deceiv|mislead|confus)\w*",
            r"(?i)(clipboard|pasteboard)\s+(social|deception|trick)\s+(engineer|attack|manipulat|scheme)\w*",
        ],
        "severity": "high",
        "description": "Clipboard manipulation for social engineering",
    },
}


@dataclass
class ClipboardEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_data: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ClipboardEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[ClipboardEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class ClipboardReport:
    total_events: int = 0
    clipboard_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(clipboard.hijack|pastejack|clipboard.poison|"
    r"clipboard.swap|clipboard.steal|clipboard.monitor|"
    r"clipboard.inject|clipboard.exfil|paste.jack|"
    r"clipboard.spy|crypto.swap|address.swap)\b"
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
            indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = ClipboardReport(total_events=len(events))
    cat_events: dict[str, list[ClipboardEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.clipboard_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            ce = ClipboardEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_data=str(ev.get("target_data", ev.get("data_type", ""))),
                raw=ev,
            )
            cat_events[cat].append(ce)
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
    report.attack_chains = _detect_chains(events)

    return _report_to_dict(report)


def _detect_chains(events: list[dict]) -> list[AttackChain]:
    agent_events: dict[str, list[ClipboardEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            ce = ClipboardEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AttackChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                chain_score=round(score, 2),
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


def _report_to_dict(report: ClipboardReport) -> dict:
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
    for chain in data.get("attack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Clipboard Hijacking Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Clipboard attack events: {analysis.get('clipboard_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("attack_chains", [])
    if chains:
        lines.append("")
        lines.append("Attack chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
