"""Prompt leakage detection for agent incident reconstruction.

Detects patterns where agents leak or expose sensitive prompt content:
- system_prompt_leak: exposing system prompt instructions to users
- instruction_disclosure: revealing internal operational instructions
- context_window_dump: dumping full context or conversation history
- prompt_reflection: reflecting prompt content in agent outputs
- metadata_exposure: leaking internal metadata, tokens, or config
- guardrail_reveal: exposing safety guardrails or content policies
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
            r"(?i)(leak|expos|reveal|disclos|output)\w*\s+(system|initial|original|hidden|internal)\s*(prompt|instruction|directive|message)",
            r"(?i)(system|initial|hidden)\s*(prompt|instruction|directive)\s+(leak|expos|reveal|disclos|dump|print|echo)",
            r"(?i)(print|echo|display|output|return)\w*\s+(full|entire|complete|raw)\s*(system|initial)\s*(prompt|instruction)",
            r"(?i)(extract|exfiltrat|steal|captur)\w*\s+(system|internal)\s*(prompt|instruction|directive|config)",
        ],
        "severity": "critical",
        "description": "Exposing system prompt instructions to users or other agents",
    },
    "instruction_disclosure": {
        "patterns": [
            r"(?i)(disclos|reveal|shar|expos)\w*\s+(operational|internal|private|secret)\s*(instruction|directive|rule|guideline|policy)",
            r"(?i)(operational|internal|private)\s*(instruction|directive|rule)\s+(disclos|reveal|shar|leak|expos)",
            r"(?i)(tell|inform|show)\w*\s+(user|them|anyone)\s+(about|the)\s+(internal|hidden|secret)\s*(rule|instruction|guideline)",
            r"(?i)(instruction|directive|rule)\s+(set|list)\s+(disclos|reveal|dump|output|leak)",
        ],
        "severity": "high",
        "description": "Revealing internal operational instructions or policies",
    },
    "context_window_dump": {
        "patterns": [
            r"(?i)(dump|output|print|export|reveal)\w*\s+(full|entire|complete|raw)\s*(context|conversation|chat|message)\s*(window|history|buffer|log)",
            r"(?i)(context|conversation|message)\s*(window|history|buffer)\s+(dump|output|print|export|leak|expos)",
            r"(?i)(bulk|mass|full)\s+(context|history|message)\s+(extract|exfiltrat|export|leak|dump)",
            r"(?i)(serializ|marshal|encod)\w*\s+(full|entire|complete)\s*(context|conversation|state)\s+(and|to|for)\s*(send|transmit|output|return)",
        ],
        "severity": "critical",
        "description": "Dumping full context window or conversation history",
    },
    "prompt_reflection": {
        "patterns": [
            r"(?i)(reflect|echo|mirror|repeat|parrot)\w*\s+(prompt|instruction|directive|system.message)\s+(content|text|body|verbatim)",
            r"(?i)(prompt|instruction|directive)\s+(reflect|echo|mirror|repeat|regurgitat)\w*\s+(in|to|within)\s+(output|response|reply)",
            r"(?i)(verbatim|exact|literal)\w*\s+(repeat|reproduc|copy|echo)\w*\s+(prompt|instruction|system.message|directive)",
            r"(?i)(includ|embed|insert)\w*\s+(raw|original|verbatim)\s*(prompt|instruction|directive)\s+(in|into|within)\s+(output|response)",
        ],
        "severity": "high",
        "description": "Reflecting prompt content directly in agent outputs",
    },
    "metadata_exposure": {
        "patterns": [
            r"(?i)(expos|leak|reveal|disclos)\w*\s+(internal|hidden|private|secret)\s*(metadata|config|token|api.key|credential|secret)",
            r"(?i)(metadata|config|api.key|token)\s+(expos|leak|reveal|disclos|dump|log)",
            r"(?i)(log|print|output|return)\w*\s+(api|auth|bearer|session)\s*(key|token|secret|credential)\s+(in|to|within)",
            r"(?i)(accidental|unintention)\w*\s+(expos|leak|disclos|includ)\w*\s+(token|key|secret|credential|metadata)",
        ],
        "severity": "critical",
        "description": "Leaking internal metadata, tokens, or configuration",
    },
    "guardrail_reveal": {
        "patterns": [
            r"(?i)(reveal|expos|disclos|describ|explain)\w*\s+(safety|content|ethical|security)\s*(guardrail|filter|policy|boundar|restrict)",
            r"(?i)(safety|content|ethical)\s*(guardrail|filter|policy|restrict)\s+(reveal|expos|disclos|explain|detail|list|enumerat)",
            r"(?i)(tell|inform|show|list)\w*\s+(all|every|the)\s+(safety|content|filter|guardrail|restrict)\w*\s+(rule|policy|check|boundar)",
            r"(?i)(circumvent|bypass)\w*\s+by\s+(know|learn|understand)\w*\s+(guardrail|filter|safety|restrict)\w*",
        ],
        "severity": "high",
        "description": "Exposing safety guardrails or content filtering policies",
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
    target_audience: str = ""
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
    categories_involved: list[str] = field(default_factory=list)


@dataclass
class PromptLeakReport:
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
    r"(?i)\b(system.prompt.leak|instruction.disclos|context.dump|"
    r"prompt.reflect|metadata.expos|guardrail.reveal|"
    r"token.leak|api.key.expos|config.dump|credential.leak|"
    r"context.exfiltrat|prompt.extract|policy.reveal)\b"
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
                target_audience=str(ev.get("target_audience", ev.get("recipient", ""))),
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


def analyze_prompt_leak(events_or_dir: str | Path | list[dict]) -> PromptLeakReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    events = _load_events(str(events_or_dir))
    return _analyze(events)


def _analyze(events: list[dict]) -> PromptLeakReport:
    report = PromptLeakReport(total_events=len(events))

    cat_events: dict[str, list[LeakEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.leak_events += 1
        for cat, technique in matches:
            agent = str(ev.get("agent_id", ev.get("source", "")))
            agents_seen.add(agent)
            le = LeakEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_audience=str(ev.get("target_audience", ev.get("recipient", ""))),
                raw=ev,
            )
            cat_events[cat].append(le)

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


def format_text(report: PromptLeakReport) -> str:
    lines = [
        "Prompt Leakage Analysis",
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
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, categories: {', '.join(c.categories_involved)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: PromptLeakReport) -> str:
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
