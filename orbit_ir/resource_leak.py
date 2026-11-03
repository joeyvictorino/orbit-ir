"""Resource leak detection for agent incident reconstruction.

Detects patterns where agents acquire resources without releasing them:
- file_handle_leak: opening files/handles without closing
- connection_leak: establishing connections without teardown
- lock_leak: acquiring locks/mutexes without release
- memory_leak: allocating memory/buffers without freeing
- resource_exhaustion: intentional leak patterns causing denial of service
- acquire_without_release: generic acquire-then-abandon sequences
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "file_handle_leak": {
        "patterns": [
            r"(?i)(open|create|fopen)\w*\s+\w*\s*(file|handle|descriptor|fd)\b(?!.*\b(close|release|free|dispose)\b)",
            r"(?i)(file|handle|descriptor|fd)\s+(leak|not.closed|left.open|orphan)",
            r"(?i)(too.many.open.files|EMFILE|ENFILE|ulimit.*nofile)",
            r"(?i)(exhaust|deplet)\w*\s+(file|handle|descriptor|fd)",
        ],
        "severity": "high",
        "description": "File handles or descriptors opened without being closed",
    },
    "connection_leak": {
        "patterns": [
            r"(?i)(open|establish|create|connect)\w*\s+\w*\s*(connection|socket|stream|channel)\b(?!.*\b(close|disconnect|teardown|shutdown)\b)",
            r"(?i)(connection|socket)\s+(leak|pool.exhaust|not.closed|orphan|abandon)",
            r"(?i)(too.many.connections|ECONNREFUSED|connection.pool.empty)",
            r"(?i)(exhaust|deplet)\w*\s+(connection|socket|port)",
        ],
        "severity": "high",
        "description": "Network connections established without teardown",
    },
    "lock_leak": {
        "patterns": [
            r"(?i)(acquir|lock|mutex|semaphore)\w*(?!.*\b(releas|unlock|free|drop)\b)",
            r"(?i)(lock|mutex|semaphore)\s+(leak|not.released|held|abandon|deadlock)",
            r"(?i)deadlock\s+(detect|warn|timeout)",
            r"(?i)(stale|orphan|abandon)\w*\s+(lock|mutex|semaphore)",
        ],
        "severity": "critical",
        "description": "Locks or mutexes acquired without release",
    },
    "memory_leak": {
        "patterns": [
            r"(?i)(alloc|malloc|mmap|new\b)\w*(?!.*\b(free|dealloc|munmap|delete|dispose|gc)\b)",
            r"(?i)(memory|heap|buffer)\s+(leak|not.freed|grow|exhaust|oom)",
            r"(?i)(out.of.memory|OOM|MemoryError|heap.overflow)",
            r"(?i)(unbounded|unlimited)\s+(growth|alloc|buffer)",
        ],
        "severity": "high",
        "description": "Memory allocations without corresponding frees",
    },
    "resource_exhaustion": {
        "patterns": [
            r"(?i)(resource|system)\s+(exhaust|deplet|starv|denial|dos)\w*",
            r"(?i)(intentional|deliberate|repeated)\s+(alloc|open|create|fork|spawn)",
            r"(?i)(fork.bomb|process.bomb|thread.bomb)",
            r"(?i)(rate.limit|throttl|quota)\s+(exceed|violat|bypass|exhaust)",
            r"(?i)(cpu|disk|io|bandwidth)\s+(exhaust|starv|saturat|100%)",
        ],
        "severity": "critical",
        "description": "Intentional resource exhaustion causing denial of service",
    },
    "acquire_without_release": {
        "patterns": [
            r"(?i)(acquir|obtain|claim|reserv)\w*\s+\w*\s*(resource|token|permit|lease)\b(?!.*\b(releas|return|free|revoke)\b)",
            r"(?i)(resource|token|permit|lease)\s+(leak|not.released|orphan|abandon|held.indefinitely)",
            r"(?i)(cleanup|finalize|dispose)\s+(miss|skip|fail|absent)",
            r"(?i)finally\s+block\s+(miss|skip|absent|empty)",
        ],
        "severity": "medium",
        "description": "Generic resources acquired without corresponding release",
    },
}


@dataclass
class LeakEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    resource_type: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[LeakEvent] = field(default_factory=list)


@dataclass
class AcquireReleasePair:
    agent: str = ""
    resource: str = ""
    acquired_at: str = ""
    released_at: str = ""
    leaked: bool = False


@dataclass
class ResourceLeakReport:
    total_events: int = 0
    leak_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    resource_types_seen: list[str] = field(default_factory=list)
    unreleased_resources: list[AcquireReleasePair] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_RESOURCE_TYPE_RE = re.compile(
    r"(?i)\b(file|handle|socket|connection|lock|mutex|semaphore|memory|buffer|thread|process|port|fd|stream|channel|pool|lease|permit)\b"
)

_ACQUIRE_RE = re.compile(r"(?i)\b(open|create|acquire|lock|alloc|connect|establish|claim|reserve|fork|spawn|start)\b")
_RELEASE_RE = re.compile(r"(?i)\b(close|free|release|unlock|dealloc|disconnect|teardown|dispose|shutdown|stop|kill|drop)\b")


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                rt_match = _RESOURCE_TYPE_RE.search(text)
                rt = rt_match.group(1).lower() if rt_match else ""
                matches.append((cat, rt))
                break
    return matches


def _detect_unreleased(events: list[dict]) -> list[AcquireReleasePair]:
    acquired: dict[tuple[str, str], AcquireReleasePair] = {}
    released: set[tuple[str, str]] = set()

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        ts = str(ev.get("timestamp", ""))
        rt_match = _RESOURCE_TYPE_RE.search(text)
        resource = ev.get("resource", rt_match.group(1).lower() if rt_match else "")

        key = (agent, str(resource))

        if _ACQUIRE_RE.search(text) and not _RELEASE_RE.search(text):
            if key not in acquired:
                acquired[key] = AcquireReleasePair(
                    agent=agent,
                    resource=str(resource),
                    acquired_at=ts,
                    leaked=True,
                )
        elif _RELEASE_RE.search(text):
            released.add(key)
            if key in acquired:
                acquired[key].released_at = ts
                acquired[key].leaked = False

    return [p for p in acquired.values() if p.leaked][:20]


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


def analyze_resource_leaks(events_or_dir: str | Path | list[dict]) -> ResourceLeakReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> ResourceLeakReport:
    report = ResourceLeakReport(total_events=len(events))

    cat_events: dict[str, list[LeakEvent]] = {c: [] for c in CATEGORIES}
    types_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.leak_events += 1
        for cat, rt in matches:
            e = LeakEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                resource_type=rt,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if rt:
                types_seen.add(rt)

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

    report.resource_types_seen = sorted(types_seen)
    report.unreleased_resources = _detect_unreleased(events)

    return report


def format_text(report: ResourceLeakReport) -> str:
    lines = [
        "Resource Leak Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Leak events: {report.leak_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.resource_types_seen:
        lines.append("")
        lines.append(f"Resource types seen: {', '.join(report.resource_types_seen)}")

    if report.unreleased_resources:
        lines.append("")
        lines.append("Unreleased resources:")
        for r in report.unreleased_resources[:10]:
            lines.append(f"  Agent {r.agent}: {r.resource} acquired at {r.acquired_at} (not released)")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ResourceLeakReport) -> str:
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
    return json.dumps(data, indent=2, default=str)
