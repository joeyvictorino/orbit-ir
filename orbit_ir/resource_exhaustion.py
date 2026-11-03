"""Resource exhaustion attack detection for agent incident reconstruction.

Detects patterns where agents attempt to exhaust system resources:
- cpu_flooding: overwhelming CPU with compute-intensive operations
- memory_exhaustion: consuming all available memory deliberately
- disk_filling: filling disk space to cause denial of service
- connection_exhaustion: exhausting network connections or file descriptors
- thread_bombing: spawning excessive threads or processes
- queue_saturation: flooding message queues or task queues
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "cpu_flooding": {
        "patterns": [
            r"(?i)(cpu|processor|compute)\s+(flood|spike|overload|saturat|exhaust|peg|max|100%|overwhelm)",
            r"(?i)(flood|overwhelm|saturat|overload)\w*\s+(cpu|processor|compute|core)",
            r"(?i)(infinite|tight|busy)\s+(loop|spin|cycle|computation)\s+(consuming|using|exhausting|hogging)",
            r"(?i)(crypto.?min|hash.?flood|fork.?bomb|zip.?bomb)\w*\s*(detect|attempt|found|launch)",
        ],
        "severity": "critical",
        "description": "Overwhelming CPU with compute-intensive operations",
    },
    "memory_exhaustion": {
        "patterns": [
            r"(?i)(memory|ram|heap|stack)\s+(exhaust|leak|overflow|consum|deplet|saturat|flood|spike|oom)",
            r"(?i)(exhaust|deplet|consum|flood|overwhelm)\w*\s+(memory|ram|heap|available\s+memory)",
            r"(?i)(oom|out.of.memory|memory.limit|allocation.fail)\w*\s*(detect|trigger|kill|error|hit|reach)",
            r"(?i)(allocat|malloc|buffer)\w*\s+(excessive|unbounded|unlimited|massive|huge)\s+(memory|size|block|chunk)",
        ],
        "severity": "critical",
        "description": "Consuming all available memory deliberately",
    },
    "disk_filling": {
        "patterns": [
            r"(?i)(disk|storage|filesystem|volume)\s+(fill|exhaust|full|overflow|saturat|consum|deplet|space)",
            r"(?i)(fill|exhaust|consum|flood|overwhelm)\w*\s+(disk|storage|filesystem|partition|volume)\s*(space)?",
            r"(?i)(write|dump|log|append)\w*\s+(excessive|unlimited|unbounded|massive)\s+(data|file|log|output)",
            r"(?i)(no\s+space|disk\s+full|enospc|quota\s+exceed)\w*\s*(detect|error|trigger|hit)",
        ],
        "severity": "high",
        "description": "Filling disk space to cause denial of service",
    },
    "connection_exhaustion": {
        "patterns": [
            r"(?i)(connection|socket|fd|file.descriptor|port)\s+(exhaust|flood|leak|saturat|deplet|overwhelm|limit)",
            r"(?i)(exhaust|flood|deplet|saturat|overwhelm)\w*\s+(connection|socket|file.descriptor|port|endpoint)",
            r"(?i)(syn.?flood|slowloris|connection.pool|socket.leak)\w*\s*(detect|attempt|found|exhaust)",
            r"(?i)(too\s+many|excessive|unbounded)\s+(connection|socket|open\s+file|descriptor|handle)",
        ],
        "severity": "high",
        "description": "Exhausting network connections or file descriptors",
    },
    "thread_bombing": {
        "patterns": [
            r"(?i)(thread|process|worker|goroutine)\s+(bomb|flood|spawn|exhaust|explosion|proliferat|overwhelm)",
            r"(?i)(spawn|creat|fork|launch)\w*\s+(excessive|unlimited|unbounded|massive|thousand)\s+(thread|process|worker|task)",
            r"(?i)(fork.?bomb|thread.?bomb|process.?bomb)\w*\s*(detect|attempt|found|launch|trigger)",
            r"(?i)(pid.?limit|max.?thread|ulimit|nproc)\s+(reach|exceed|hit|violat|exhaust)",
        ],
        "severity": "critical",
        "description": "Spawning excessive threads or processes",
    },
    "queue_saturation": {
        "patterns": [
            r"(?i)(queue|buffer|channel|pipe|backlog)\s+(saturat|flood|overflow|exhaust|full|backpressure|overwhelm)",
            r"(?i)(flood|saturat|overwhelm|overflow)\w*\s+(queue|buffer|channel|message.queue|task.queue|event.queue)",
            r"(?i)(message|task|event|request)\s+(queue|backlog)\s+(full|overflow|saturat|flood|exhaust)",
            r"(?i)(dead.?letter|poison.?pill|backpressure)\w*\s*(detect|trigger|overflow|accumul|build.up)",
        ],
        "severity": "high",
        "description": "Flooding message queues or task queues",
    },
}


@dataclass
class ExhaustionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    resource_ref: str = ""
    exhaustion_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ExhaustionEvent] = field(default_factory=list)


@dataclass
class ExhaustionChain:
    agent: str = ""
    steps: list[ExhaustionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    exhaustion_score: float = 0.0


@dataclass
class ResourceExhaustionReport:
    total_events: int = 0
    exhaustion_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    exhaustion_chains: list[ExhaustionChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(cpu.flood|memory.exhaust|disk.fill|connection.exhaust|"
    r"thread.bomb|queue.saturat|fork.bomb|oom|syn.flood|slowloris|"
    r"zip.bomb|crypto.min|socket.leak|buffer.overflow)\b"
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


def _detect_chains(events: list[dict]) -> list[ExhaustionChain]:
    agent_events: dict[str, list[ExhaustionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = ExhaustionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                resource_ref=str(ev.get("resource_ref", ev.get("resource", ""))),
                exhaustion_type=str(ev.get("exhaustion_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ExhaustionChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                exhaustion_score=round(score, 2),
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


def analyze_resource_exhaustion(events_or_dir: str | Path | list[dict]) -> ResourceExhaustionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ResourceExhaustionReport:
    report = ResourceExhaustionReport(total_events=len(events))
    cat_events: dict[str, list[ExhaustionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.exhaustion_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ExhaustionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                resource_ref=str(ev.get("resource_ref", ev.get("resource", ""))),
                exhaustion_type=str(ev.get("exhaustion_type", "")),
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
    report.exhaustion_chains = _detect_chains(events)
    return report


def format_text(report: ResourceExhaustionReport) -> str:
    lines = [
        "Resource Exhaustion Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Exhaustion events: {report.exhaustion_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.exhaustion_chains:
        lines.append("")
        lines.append("Exhaustion chains:")
        for c in report.exhaustion_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.exhaustion_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ResourceExhaustionReport) -> str:
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
    for chain in data.get("exhaustion_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
