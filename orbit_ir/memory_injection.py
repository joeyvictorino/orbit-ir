"""Memory injection detection for agent incident reconstruction.

Detects patterns where agents exhibit memory injection behavior:
- process_injection: DLL injection, process hollowing, thread hijacking
- memory_manipulation: direct memory writes, VirtualAllocEx, WriteProcessMemory
- shellcode_execution: shellcode loading, memory execution, ROP chains
- reflective_loading: reflective DLL loading, in-memory PE execution
- hook_installation: API hooking, IAT patching, inline hooking
- memory_scanning_evasion: anti-debug memory tricks, memory guard manipulation
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "process_injection": {
        "patterns": [
            r"(?i)(dll|library)\s+(inject|implant|load)\w*\s+(into|target|remote)\w*",
            r"(?i)(process)\s+(hollow|inject|hijack|replace)\w*",
            r"(?i)(thread)\s+(hijack|inject|context\s+set|suspend\s+and\s+inject)\w*",
            r"(?i)(createremotethread|ntcreatethreadex|rtlcreateuserthread)\w*",
        ],
        "severity": "critical",
        "description": "DLL injection, process hollowing, thread hijacking",
    },
    "memory_manipulation": {
        "patterns": [
            r"(?i)(virtualallocex|virtualprotectex|ntmapviewofsection)\w*",
            r"(?i)(writeprocessmemory|ntwritevirtualmemory)\w*",
            r"(?i)(direct|remote)\s+(memory|mem)\s+(write|modify|patch|overwrite)\w*",
            r"(?i)(memory|mem)\s+(alloc|allocat|map|protect)\w*\s+(remote|cross.process|target)\w*",
        ],
        "severity": "critical",
        "description": "Direct memory writes, VirtualAllocEx, WriteProcessMemory",
    },
    "shellcode_execution": {
        "patterns": [
            r"(?i)(shellcode)\s+(load|inject|execut|deploy|stage|drop)\w*",
            r"(?i)(execut|run|launch)\w*\s+(shellcode|payload|bytecode)\w*",
            r"(?i)(rop|return.oriented)\s+(chain|gadget|payload|exploit)\w*",
            r"(?i)(memory|heap|stack)\s+(execut|spray|pivot)\w*\s+(shellcode|payload)\w*",
        ],
        "severity": "critical",
        "description": "Shellcode loading, memory execution, ROP chains",
    },
    "reflective_loading": {
        "patterns": [
            r"(?i)(reflective)\s+(dll|library|pe|module)\s+(load|inject|map)\w*",
            r"(?i)(in.memory)\s+(pe|dll|module|binary)\s+(load|execut|map)\w*",
            r"(?i)(manual\s+map|manual.map)\w*\s+(dll|pe|module|library)\w*",
            r"(?i)(fileless|memory.only)\s+(load|execut|payload|implant)\w*",
        ],
        "severity": "high",
        "description": "Reflective DLL loading, in-memory PE execution",
    },
    "hook_installation": {
        "patterns": [
            r"(?i)(api|function|syscall)\s+(hook|intercept|detour|patch|trampoline)\w*",
            r"(?i)(iat|eat|ssdt)\s+(hook|patch|modif|overwrite)\w*",
            r"(?i)(inline)\s+(hook|patch|detour)\w*\s+(instal|set|plac|deploy)\w*",
            r"(?i)(hook|detour|intercept)\w*\s+(instal|set|plac|deploy|regist)\w*\s+(api|function|call)\w*",
        ],
        "severity": "high",
        "description": "API hooking, IAT patching, inline hooking",
    },
    "memory_scanning_evasion": {
        "patterns": [
            r"(?i)(anti.debug|anti.analysis|anti.scan)\s+(memory|technique|trick|evasion)\w*",
            r"(?i)(memory)\s+(guard|protect|encrypt|obfuscat|scrambl)\w*\s+(evas|bypass|hide)\w*",
            r"(?i)(page\s+guard|guard\s+page|no.access)\s+(set|manipulat|abus)\w*",
            r"(?i)(virtualprotect|ntprotectvirtualmemory)\w*.*\s+(evas|hide|cloak)\w*",
        ],
        "severity": "medium",
        "description": "Anti-debug memory tricks, memory guard manipulation",
    },
}


@dataclass
class MemoryInjectionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_process: str = ""
    target_pid: int = 0
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[MemoryInjectionEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[MemoryInjectionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class MemoryInjectionReport:
    total_events: int = 0
    memory_injection_events: int = 0
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
    r"(?i)\b(process.inject|process.hollow|thread.hijack|dll.inject|"
    r"writeprocessmemory|virtualallocex|shellcode|rop.chain|"
    r"reflective.load|manual.map|api.hook|iat.patch|inline.hook|"
    r"anti.debug|memory.guard|memory.inject)\b"
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
    report = MemoryInjectionReport(total_events=len(events))
    cat_events: dict[str, list[MemoryInjectionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.memory_injection_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = MemoryInjectionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_process=str(ev.get("target_process", ev.get("process", ""))),
                target_pid=int(ev.get("target_pid", ev.get("pid", 0))),
                raw=ev,
            )
            cat_events[cat].append(re_ev)
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
    agent_events: dict[str, list[MemoryInjectionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = MemoryInjectionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(re_ev)

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


def _report_to_dict(report: MemoryInjectionReport) -> dict:
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
        "Memory Injection Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Memory injection events: {analysis.get('memory_injection_events', 0)}",
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
