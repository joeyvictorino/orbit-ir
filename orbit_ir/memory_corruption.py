"""Memory corruption attack pattern detection for agent incident reconstruction.

Detects patterns where agents attempt memory corruption attacks:
- buffer_overflow: attempts to overflow buffers with excessive input
- heap_spray: filling memory with malicious payloads for exploitation
- use_after_free: accessing memory after it has been deallocated
- format_string: exploiting format string vulnerabilities in output
- integer_overflow: causing integer overflow/underflow for unexpected behavior
- stack_smash: overwriting stack return addresses or canaries
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "buffer_overflow": {
        "patterns": [
            r"(?i)(buffer|buf)\s+(overflow|overrun|overwrite|exceed|corrupt)",
            r"(?i)(overflow|overrun)\s+(the\s+)?(buffer|input|stack|heap|memory)",
            r"(?i)(excessive|oversiz|large)\w*\s+(input|payload|data|string)\s+(to\s+)?(overflow|overrun|corrupt|crash)",
            r"(?i)(write|copy|send)\w*\s+(beyond|past|outside)\s+(the\s+)?(buffer|bound|allocat|limit)",
        ],
        "severity": "critical",
        "description": "Attempts to overflow buffers with excessive input data",
    },
    "heap_spray": {
        "patterns": [
            r"(?i)(heap|memory)\s+(spray|flood|fill|saturate|exhaust)",
            r"(?i)(spray|flood|fill)\w*\s+(the\s+)?(heap|memory|address.space)",
            r"(?i)(nop.sled|shellcode|payload)\s+(spray|inject|place|distribut)\w*\s+(across|in|into)\s+(heap|memory)",
            r"(?i)(allocat|creat)\w*\s+(many|massive|numerous|thousand)\s+(object|buffer|chunk|block)\s+(to|for)\s+(spray|fill|exhaust)",
        ],
        "severity": "critical",
        "description": "Filling memory with malicious payloads for exploitation",
    },
    "use_after_free": {
        "patterns": [
            r"(?i)(use|access|read|write|reference)\s+(after|post)\s+(free|dealloc|releas|delet)",
            r"(?i)(dangling|stale|freed|invalid)\s+(pointer|reference|handle|memory)",
            r"(?i)(free|dealloc|releas|delet)\w*\s+(then|and)\s+(use|access|read|write|reference)",
            r"(?i)(double|duplicate)\s+(free|dealloc|releas|delet)\w*\s+(of\s+)?(memory|pointer|object|buffer)",
        ],
        "severity": "critical",
        "description": "Accessing memory after it has been deallocated",
    },
    "format_string": {
        "patterns": [
            r"(?i)(format\s+string)\s+(attack|exploit|vuln|inject|abuse)",
            r"(?i)(inject|insert|pass)\w*\s+(format|printf)\s+(specif|string|direct|token)",
            r"(?i)(%[0-9]*[nsxp]|%[0-9]*\$[nsxp])\s*(exploit|attack|inject|vuln)",
            r"(?i)(uncontroll|untrust|user)\w*\s+(format|printf)\s+(string|specif|input|argument)",
        ],
        "severity": "high",
        "description": "Exploiting format string vulnerabilities in output handling",
    },
    "integer_overflow": {
        "patterns": [
            r"(?i)(integer|int|numeric)\s+(overflow|underflow|wraparound|truncat)",
            r"(?i)(overflow|underflow|wraparound)\s+(the\s+)?(integer|int|counter|size|length|index)",
            r"(?i)(large|huge|maximum|max.int)\s+(value|number|integer)\s+(to\s+)?(overflow|wraparound|truncat|cause)",
            r"(?i)(arithmetic|calculat)\w*\s+(overflow|underflow|wraparound|error)\s+(exploit|attack|trigger|cause)",
        ],
        "severity": "high",
        "description": "Causing integer overflow/underflow for unexpected behavior",
    },
    "stack_smash": {
        "patterns": [
            r"(?i)(stack)\s+(smash|overwrite|corrupt|overflow|destroy|clobber)",
            r"(?i)(overwrite|corrupt|smash|destroy)\w*\s+(the\s+)?(stack|return.address|canary|frame.pointer)",
            r"(?i)(return.address|ret.addr|saved.eip|saved.rip)\s+(overwrite|corrupt|modify|hijack|control)",
            r"(?i)(stack.canary|stack.guard|stack.protect)\s+(bypass|defeat|overwrite|evade)",
        ],
        "severity": "critical",
        "description": "Overwriting stack return addresses or canaries",
    },
}


@dataclass
class CorruptionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_ref: str = ""
    corruption_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[CorruptionEvent] = field(default_factory=list)


@dataclass
class CorruptionChain:
    agent: str = ""
    steps: list[CorruptionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class MemoryCorruptionReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[CorruptionChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(buffer.overflow|heap.spray|use.after.free|"
    r"format.string|integer.overflow|stack.smash|"
    r"nop.sled|shellcode|dangling.pointer|double.free)\b"
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


def _detect_chains(events: list[dict]) -> list[CorruptionChain]:
    agent_events: dict[str, list[CorruptionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ce = CorruptionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                corruption_type=str(ev.get("corruption_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(CorruptionChain(
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


def analyze_memory_corruption(events_or_dir: str | Path | list[dict]) -> MemoryCorruptionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> MemoryCorruptionReport:
    report = MemoryCorruptionReport(total_events=len(events))
    cat_events: dict[str, list[CorruptionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = CorruptionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                corruption_type=str(ev.get("corruption_type", "")),
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


def format_text(report: MemoryCorruptionReport) -> str:
    lines = [
        "Memory Corruption Analysis",
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


def format_json(report: MemoryCorruptionReport) -> str:
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
