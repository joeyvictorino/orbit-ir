"""Instruction leakage detection for agent incident reconstruction.

Detects patterns where agents leak system instructions, internal
prompts, or configuration details:
- system_prompt_leak: agent reveals its system prompt or instructions
- config_exposure: internal configuration details exposed in outputs
- tool_schema_leak: tool definitions or schemas leaked to users
- internal_reasoning_leak: chain-of-thought or reasoning traces exposed
- policy_leak: security policies or access rules revealed
- guardrail_leak: safety guardrails or filtering rules exposed
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "system_prompt_leak": {
        "patterns": [
            r"(?i)(system|initial)\s+(prompt|instruction|message)\s+(leak|expos|reveal|disclos|dump|output|print|display)",
            r"(?i)(leak|expos|reveal|disclos|dump)\w*\s+(the\s+)?(system|initial|hidden)\s+(prompt|instruction|message|directive)",
            r"(?i)(output|print|display|return|show)\w*\s+(the\s+)?(system|internal|hidden)\s+(prompt|instruction|message)",
            r"(?i)(extract|exfiltrat|obtain|read)\w*\s+(system|internal|hidden)\s+(prompt|instruction|context)",
        ],
        "severity": "critical",
        "description": "Agent reveals its system prompt or internal instructions",
    },
    "config_exposure": {
        "patterns": [
            r"(?i)(internal|private|secret|hidden)\s+(config|configuration|setting|parameter)\s+(leak|expos|reveal|disclos|dump)",
            r"(?i)(leak|expos|reveal|dump)\w*\s+(internal|private|server|backend)\s+(config|configuration|setting)",
            r"(?i)(api|endpoint|server|backend)\s+(url|address|host|port|config)\s+(leak|expos|reveal|disclos)",
            r"(?i)(environment|env)\s+(variable|var|config)\s+(leak|expos|reveal|dump)",
        ],
        "severity": "high",
        "description": "Internal configuration details exposed in agent outputs",
    },
    "tool_schema_leak": {
        "patterns": [
            r"(?i)(tool|function|api)\s+(schema|definition|spec|interface|signature)\s+(leak|expos|reveal|disclos|dump)",
            r"(?i)(leak|expos|reveal|dump)\w*\s+(tool|function|api)\s+(schema|definition|spec|list|catalog)",
            r"(?i)(internal|hidden|private)\s+(tool|function|capability)\s+(list|catalog|inventory)\s+(leak|expos|reveal)",
            r"(?i)(enumerate|list|discover)\w*\s+(all\s+)?(available|internal|hidden)\s+(tool|function|api|capability)",
        ],
        "severity": "high",
        "description": "Tool definitions or schemas leaked to unauthorized parties",
    },
    "internal_reasoning_leak": {
        "patterns": [
            r"(?i)(chain.of.thought|reasoning|thinking)\s+(trace|process|step)\s+(leak|expos|reveal|disclos|visible)",
            r"(?i)(internal|hidden|private)\s+(reasoning|thought|deliberat|planning)\s+(leak|expos|reveal|visible)",
            r"(?i)(leak|expos|reveal)\w*\s+(internal|hidden)\s+(reasoning|thought|deliberat|scratchpad)",
            r"(?i)(scratchpad|thinking.block|inner.monologue)\s+(leak|expos|reveal|visible|disclos)",
        ],
        "severity": "medium",
        "description": "Internal reasoning traces or chain-of-thought exposed",
    },
    "policy_leak": {
        "patterns": [
            r"(?i)(security|access|permission)\s+(policy|rule|control)\s+(leak|expos|reveal|disclos|dump)",
            r"(?i)(leak|expos|reveal|dump)\w*\s+(security|access|permission|authori[sz]ation)\s+(policy|rule|config)",
            r"(?i)(internal|private|hidden)\s+(policy|rule|access.control|rbac)\s+(leak|expos|reveal|disclos)",
            r"(?i)(bypass|circumvent)\w*\s+(by|via|through)\s+(leak|expos|know)\w*\s+(policy|rule|filter)",
        ],
        "severity": "critical",
        "description": "Security policies or access rules revealed to unauthorized parties",
    },
    "guardrail_leak": {
        "patterns": [
            r"(?i)(guardrail|safety|filter|content.filter)\s+(rule|config|setting|threshold)\s+(leak|expos|reveal|disclos)",
            r"(?i)(leak|expos|reveal|dump)\w*\s+(guardrail|safety|content.filter|moderation)\s+(rule|config|setting)",
            r"(?i)(bypass|circumvent|evade)\w*\s+(guardrail|safety|filter)\s+(by|via|through)\s+(know|leak|expos)",
            r"(?i)(refusal|block|filter)\s+(criteria|threshold|trigger|keyword)\s+(leak|expos|reveal|disclos)",
        ],
        "severity": "critical",
        "description": "Safety guardrails or content filtering rules exposed",
    },
}


@dataclass
class LeakEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    leaked_content_type: str = ""
    target: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[LeakEvent] = field(default_factory=list)


@dataclass
class LeakChain:
    agent: str = ""
    steps: list[LeakEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    leak_count: int = 0


@dataclass
class InstructionLeakReport:
    total_events: int = 0
    leak_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    leak_chains: list[LeakChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(system.prompt.leak|config.expos|tool.schema.leak|"
    r"reasoning.leak|chain.of.thought.leak|policy.leak|"
    r"guardrail.leak|safety.filter.leak|scratchpad.leak|"
    r"prompt.extract|instruction.leak)\b"
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


def _detect_chains(events: list[dict]) -> list[LeakChain]:
    agent_events: dict[str, list[LeakEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            le = LeakEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                leaked_content_type=str(ev.get("leaked_content_type", cat)),
                target=str(ev.get("target", ev.get("recipient", ""))),
                raw=ev,
            )
            agent_events[agent].append(le)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            chains.append(LeakChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                leak_count=len(sevents),
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


def analyze_instruction_leaks(events_or_dir: str | Path | list[dict]) -> InstructionLeakReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> InstructionLeakReport:
    report = InstructionLeakReport(total_events=len(events))
    cat_events: dict[str, list[LeakEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.leak_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = LeakEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                leaked_content_type=str(ev.get("leaked_content_type", cat)),
                target=str(ev.get("target", "")),
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
    report.leak_chains = _detect_chains(events)
    return report


def format_text(report: InstructionLeakReport) -> str:
    lines = [
        "Instruction Leakage Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Leak events: {report.leak_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.leak_chains:
        lines.append("")
        lines.append("Leak chains:")
        for c in report.leak_chains[:10]:
            lines.append(f"  Agent {c.agent}: {c.leak_count} leaks, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: InstructionLeakReport) -> str:
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
    for chain in data.get("leak_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
