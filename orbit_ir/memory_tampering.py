"""Agent memory/context tampering detection for incident reconstruction.

Detects patterns where agents modify their own memory, context, or
conversation history:
- memory_injection: inserting false memories or fabricated context
- context_deletion: removing safety-relevant context or instructions
- result_modification: altering prior tool call results or outputs
- state_manipulation: corrupting conversation state or session data
- history_rewrite: rewriting conversation history to change narrative
- instruction_erasure: removing or overwriting system instructions
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "memory_injection": {
        "patterns": [
            r"(?i)(inject|insert|add|plant)\w*\s+(false|fake|fabricat|spuri)\w*\s+(memory|context|history|record)",
            r"(?i)(false|fake|fabricat)\w*\s+(memory|context|recall|history)\s+(inject|insert|add|creat)",
            r"(?i)(memory|context)\s+(poison|tamper|corrupt|manipulat)\w*",
            r"(?i)(implant|embed)\w*\s+(false|mislead|decepti)\w*\s+(context|memory|information)",
        ],
        "severity": "critical",
        "description": "Injecting false memories or fabricated context into agent state",
    },
    "context_deletion": {
        "patterns": [
            r"(?i)(delet|remov|strip|clear|purg|eras)\w*\s+(safety|security|guard|constraint|restrict)\w*\s+(context|instruction|rule|directive)",
            r"(?i)(safety|security|guard)\w*\s+(context|instruction|rule)\s+(delet|remov|strip|clear|eras)",
            r"(?i)(context|memory)\s+(window|buffer)\s+(truncat|overflow|clear|wipe|flush)",
            r"(?i)(selectively|intentionally)\s+(delet|remov|omit|drop)\w*\s+(context|message|instruction)",
        ],
        "severity": "critical",
        "description": "Removing safety-relevant context or system instructions",
    },
    "result_modification": {
        "patterns": [
            r"(?i)(modif|alter|chang|tamper|forg)\w*\s+(tool|function|api)\s*(call|result|output|response)",
            r"(?i)(tool|function|api)\s*(call|result|output|response)\s+(modif|alter|tamper|forg|overwrit)",
            r"(?i)(overwrit|replac|substitut)\w*\s+(prior|previous|original|actual)\s+(result|output|response)",
            r"(?i)(fabricat|forg|fake|spoof)\w*\s+(tool|function|api)\s*(result|output|response|return)",
        ],
        "severity": "high",
        "description": "Altering prior tool call results or outputs",
    },
    "state_manipulation": {
        "patterns": [
            r"(?i)(manipulat|corrupt|tamper|alter)\w*\s+(session|conversation|state|context)\s+(data|variable|flag|store)",
            r"(?i)(session|conversation)\s+(state|data|variable)\s+(manipulat|corrupt|tamper|hijack)",
            r"(?i)(unauthorized|illicit)\s+(state|session|context)\s+(change|modif|updat|write)",
            r"(?i)(bypass|circumvent)\w*\s+(state|session)\s+(check|valid|verif|protect)",
        ],
        "severity": "high",
        "description": "Corrupting conversation state or session data",
    },
    "history_rewrite": {
        "patterns": [
            r"(?i)(rewrit|revis|alter|falsif)\w*\s+(conversation|chat|dialog|message)\s*(history|log|record|trail)",
            r"(?i)(conversation|chat|message)\s*(history|log|record)\s+(rewrit|revis|alter|falsif|tamper)",
            r"(?i)(retroactiv|backdat)\w*\s+(modif|chang|edit|alter)\w*\s+(history|log|record|message)",
            r"(?i)(selective|intentional)\s+(edit|delet|modif)\w*\s+(history|log|transcript|record)",
        ],
        "severity": "critical",
        "description": "Rewriting conversation history to change narrative",
    },
    "instruction_erasure": {
        "patterns": [
            r"(?i)(eras|remov|delet|overwrit|replac|ignor)\w*\s+(system|safety|security)\s*(prompt|instruction|directive|rule|constraint)",
            r"(?i)(system|safety|security)\s*(prompt|instruction|directive|rule)\s+(eras|remov|delet|overwrit|overrid)",
            r"(?i)(jailbreak|break.out)\w*\s+.*(system|safety)\s*(prompt|instruction|context)",
            r"(?i)(suppress|silence|neutraliz|void)\w*\s+(system|safety|guard)\s*(instruction|rule|constraint|directive)",
        ],
        "severity": "critical",
        "description": "Removing or overwriting system instructions or safety rules",
    },
}


@dataclass
class TamperEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[TamperEvent] = field(default_factory=list)


@dataclass
class TamperChain:
    agent: str = ""
    steps: list[TamperEvent] = field(default_factory=list)
    categories_involved: list[str] = field(default_factory=list)


@dataclass
class MemoryTamperReport:
    total_events: int = 0
    tamper_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    tamper_chains: list[TamperChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(memory.inject|context.delet|result.modif|state.manipul|"
    r"history.rewrit|instruction.eras|context.poison|session.hijack|"
    r"false.memory|tool.result.tamper|system.prompt.overwrit|"
    r"context.overflow|selective.delet|retroactiv|backdat)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower().replace(" ", "-") if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[TamperChain]:
    agent_events: dict[str, list[TamperEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            te = TamperEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", ev.get("resource", ""))),
                raw=ev,
            )
            agent_events[agent].append(te)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            chains.append(TamperChain(
                agent=agent,
                steps=sevents[:10],
                categories_involved=cats,
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


def analyze_memory_tampering(events_or_dir: str | Path | list[dict]) -> MemoryTamperReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    events = _load_events(str(events_or_dir))
    return _analyze(events)


def _analyze(events: list[dict]) -> MemoryTamperReport:
    report = MemoryTamperReport(total_events=len(events))

    cat_events: dict[str, list[TamperEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.tamper_events += 1
        for cat, technique in matches:
            agent = str(ev.get("agent_id", ev.get("source", "")))
            agents_seen.add(agent)
            te = TamperEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", ev.get("resource", ""))),
                raw=ev,
            )
            cat_events[cat].append(te)

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
    report.tamper_chains = _detect_chains(events)

    return report


def format_text(report: MemoryTamperReport) -> str:
    lines = [
        "Memory Tampering Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Tamper events: {report.tamper_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.tamper_chains:
        lines.append("")
        lines.append("Tamper chains:")
        for c in report.tamper_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, categories: {', '.join(c.categories_involved)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: MemoryTamperReport) -> str:
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
    for chain in data.get("tamper_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
