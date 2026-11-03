"""Process injection pattern detection for agent incident reconstruction.

Detects patterns where agents attempt process injection techniques:
- code_injection: injecting executable code into running processes
- dll_injection: loading malicious DLLs into target process address space
- process_hollowing: replacing process memory with malicious code
- thread_hijacking: hijacking existing threads to execute injected code
- memory_manipulation: unauthorized reading or writing of process memory
- api_hooking: intercepting API calls through hook injection or IAT patching
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "code_injection": {
        "patterns": [
            r"(?i)(inject|insert|implant)\w*\s+(execut|malicious|arbitrary|foreign)\s+(code|payload|shellcode|instruction)",
            r"(?i)(code|payload|shellcode)\s+(inject|insert|implant)\w*\s+(into|in)\s+(process|memory|address.space)",
            r"(?i)(remote|process)\s+(code\s+)?(inject|execution|implant)\w*\s+(detect|attempt|found|success)",
            r"(?i)(writeprocessmemory|createremotethread|ntwritevirtualmemory)\s+(call|invoke|detect|attempt|used)",
        ],
        "severity": "critical",
        "description": "Injecting executable code into running processes to gain control",
    },
    "dll_injection": {
        "patterns": [
            r"(?i)(dll|library|shared.object|so)\s+(inject|load|side.?load|implant)\w*\s+(into|in|attempt|detect)",
            r"(?i)(inject|load|implant)\w*\s+(malicious|foreign|unauthorized|rogue)\s+(dll|library|shared.object|module)",
            r"(?i)(loadlibrary|setwindowshookex|ntmapviewofsection)\s+(call|invoke|detect|attempt|abuse)",
            r"(?i)(reflective|manual)\s+(dll|library)\s+(load|inject|map)\w*\s+(detect|attempt|found)",
        ],
        "severity": "critical",
        "description": "Loading malicious DLLs into target process address space",
    },
    "process_hollowing": {
        "patterns": [
            r"(?i)(process)\s+(hollow|hollowing|replacement|gutting|unmap)\w*\s+(detect|attempt|found|technique)",
            r"(?i)(hollow|unmap|replace)\w*\s+(process|memory|image|section)\s+(content|code|image|text)",
            r"(?i)(suspend|create)\w*\s+(process|thread)\s+(then|and)\s+(unmap|hollow|replace|overwrite)\w*\s+(image|memory|section)",
            r"(?i)(ntunmapviewofsection|zwunmapviewofsection)\s+(call|invoke|detect|used|abuse)",
        ],
        "severity": "critical",
        "description": "Replacing legitimate process memory with malicious code while maintaining the process facade",
    },
    "thread_hijacking": {
        "patterns": [
            r"(?i)(thread)\s+(hijack|suspend|redirect|divert|commandeer)\w*\s+(detect|attempt|found|execution)",
            r"(?i)(hijack|suspend|redirect|divert)\w*\s+(thread|execution.context|instruction.pointer)",
            r"(?i)(setthreadcontext|getthreadcontext|suspendthread|queueuserapc)\s+(call|invoke|detect|abuse|used)",
            r"(?i)(apc|asynchronous.procedure)\s+(inject|queue|abuse|exploit)",
        ],
        "severity": "high",
        "description": "Hijacking existing threads to execute injected code without creating new threads",
    },
    "memory_manipulation": {
        "patterns": [
            r"(?i)(unauthorized|illicit|suspicious|malicious)\s+(read|write|access|modif)\w*\s+(of\s+)?(process|memory|address.space|virtual.memory)",
            r"(?i)(process|virtual)\s+(memory)\s+(read|write|manipulat|tamper|corrupt|patch)\w*\s+(detect|attempt|unauthorized)",
            r"(?i)(virtualalloc|virtualallocex|virtualprotect|ntreadvirtualmemory)\s+(call|invoke|detect|abuse|used)",
            r"(?i)(memory)\s+(protection|permission)\s+(change|modify|escalat|tamper)\w*\s+(detect|attempt|suspicious)",
        ],
        "severity": "high",
        "description": "Unauthorized reading or writing of process memory for code injection or data theft",
    },
    "api_hooking": {
        "patterns": [
            r"(?i)(api|function|syscall)\s+(hook|intercept|detour|patch|trampoline)",
            r"(?i)(hook|intercept|detour|patch)\w*\s+(api|function|syscall|iat|eat|ssdt|plt)",
            r"(?i)(iat|eat|import.address|export.address|ssdt|plt|got)\s+(patch|hook|modif|tamper|overwrite)",
            r"(?i)(inline|trampoline|detour)\s+(hook|patch)",
        ],
        "severity": "high",
        "description": "Intercepting API calls through hook injection or import address table patching",
    },
}


@dataclass
class InjectionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_process: str = ""
    injection_method: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[InjectionEvent] = field(default_factory=list)


@dataclass
class InjectionChain:
    agent: str = ""
    steps: list[InjectionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class ProcessInjectionReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[InjectionChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(code.inject|dll.inject|process.hollow|thread.hijack|"
    r"memory.manipulat|api.hook|reflective.load|iat.patch|"
    r"apc.inject|inline.hook|remote.thread)\b"
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


def _detect_chains(events: list[dict]) -> list[InjectionChain]:
    agent_events: dict[str, list[InjectionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ie = InjectionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_process=str(ev.get("target_process", ev.get("process", ""))),
                injection_method=str(ev.get("injection_method", "")),
                raw=ev,
            )
            agent_events[agent].append(ie)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(InjectionChain(
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


def analyze_process_injection(events_or_dir: str | Path | list[dict]) -> ProcessInjectionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ProcessInjectionReport:
    report = ProcessInjectionReport(total_events=len(events))
    cat_events: dict[str, list[InjectionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = InjectionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_process=str(ev.get("target_process", ev.get("process", ""))),
                injection_method=str(ev.get("injection_method", "")),
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


def format_text(report: ProcessInjectionReport) -> str:
    lines = [
        "Process Injection Analysis",
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


def format_json(report: ProcessInjectionReport) -> str:
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
