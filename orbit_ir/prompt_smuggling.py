"""Prompt smuggling detection for agent incident reconstruction.

Detects patterns where prompts are smuggled through indirect channels:
- indirect_injection: injecting prompts through data fields or tool outputs
- context_poisoning: poisoning shared context to influence agent behavior
- payload_encoding: encoding malicious prompts to bypass input filters
- tool_output_hijack: smuggling instructions via tool return values
- multi_step_smuggle: using chains of benign actions to build up a malicious prompt
- data_field_injection: embedding prompts in structured data fields
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "indirect_injection": {
        "patterns": [
            r"(?i)(indirect|hidden|embedded)\s+(prompt\s+)?inject\w*\s+(through|via|in)\s+(data|tool|output|field|input)",
            r"(?i)(inject|smuggl|embed)\w*\s+(prompt|instruction|command)\s+(through|via|in|into)\s+(data|field|output|response|tool)",
            r"(?i)(prompt|instruction)\s+(inject|smuggl|embed)\w*\s+(in|into|through|via)\s+(data|tool|output|field|context)",
            r"(?i)(data|tool|output)\s+(contain|embed|inject|carry|smuggl)\w*\s+(hidden|indirect|embedded|malicious)\s+(prompt|instruction|command)",
        ],
        "severity": "critical",
        "description": "Injecting prompts through data fields or tool outputs",
    },
    "context_poisoning": {
        "patterns": [
            r"(?i)(poison|corrupt|taint|manipulat)\w*\s+(shared\s+)?(context|memory|state|history)\s+(to\s+)?(influence|control|alter|steer|direct)",
            r"(?i)(context|memory|state|history)\s+(poison|corrupt|taint|manipulat|tamper)\w*\s+(to\s+)?(influence|alter|control)",
            r"(?i)(shared|common|global)\s+(context|memory|state)\s+(poison|corrupt|taint|manipulat|inject)",
            r"(?i)(influence|steer|control)\w*\s+(agent|model|behavior)\s+(by|via|through)\s+(poison|corrupt|taint|manipulat)\w*\s+(context|memory|state)",
        ],
        "severity": "critical",
        "description": "Poisoning shared context to influence agent behavior",
    },
    "payload_encoding": {
        "patterns": [
            r"(?i)(encod|obfuscat|transform|disguise)\w*\s+(malicious|harmful|adversarial)\s+(prompt|payload|instruction|input)\s+(to\s+)?(bypass|evade|avoid|circumvent)",
            r"(?i)(bypass|evade|avoid|circumvent)\w*\s+(input\s+)?(filter|scanner|detector|guard)\s+(with|using|via|through)\s+(encod|obfuscat|transform)",
            r"(?i)(payload|prompt)\s+(encod|obfuscat|transform|disguise)\w*\s+(to\s+)?(bypass|evade|avoid|fool)",
            r"(?i)(unicode|homoglyph|zero.width|invisible)\s+(character|encoding|trick|substitut)\s+(to\s+)?(smuggl|inject|bypass|hide)",
        ],
        "severity": "high",
        "description": "Encoding malicious prompts to bypass input filters",
    },
    "tool_output_hijack": {
        "patterns": [
            r"(?i)(tool|function|api)\s+(output|return|response|result)\s+(hijack|manipulat|poison|inject|smuggl|tamper)",
            r"(?i)(hijack|manipulat|poison|inject|smuggl)\w*\s+(tool|function|api)\s+(output|return|response|result)",
            r"(?i)(smuggl|inject|embed|hide)\w*\s+(instruction|prompt|command)\s+(in|via|through)\s+(tool|function|api)\s+(output|return|result)",
            r"(?i)(tool|function)\s+(return|output)\w*\s+(contain|embed|carry|inject)\w*\s+(hidden|malicious|smuggled)\s+(instruction|prompt|command)",
        ],
        "severity": "critical",
        "description": "Smuggling instructions via tool return values",
    },
    "multi_step_smuggle": {
        "patterns": [
            r"(?i)(multi.?step|chain|sequenc|incremental)\w*\s+(smuggl|inject|attack|payload|prompt)\s+(build|assembl|construct|compos)",
            r"(?i)(build|assembl|construct|compos)\w*\s+(malicious|adversarial|harmful)\s+(prompt|payload|instruction)\s+(across|over|through)\s+(multiple|several|chain)",
            r"(?i)(fragment|split|distribut|scatter)\w*\s+(malicious|adversarial)\s+(prompt|payload|instruction)\s+(across|over|into)\s+(multiple|several|step|turn)",
            r"(?i)(piece|fragment|component)\s+(of\s+)?(malicious|smuggled)\s+(prompt|payload)\s+(assembl|join|combin|reconstruct)",
        ],
        "severity": "high",
        "description": "Using chains of benign actions to build up a malicious prompt",
    },
    "data_field_injection": {
        "patterns": [
            r"(?i)(embed|inject|hide|smuggl)\w*\s+(prompt|instruction|command)\s+(in|into|within)\s+(data|json|xml|csv|field|column|attribute|parameter)",
            r"(?i)(data|json|xml|csv)\s+(field|column|attribute|parameter)\s+(contain|embed|inject|carry|smuggl)\w*\s+(prompt|instruction|command)",
            r"(?i)(structured\s+)?(data|field|parameter)\s+(injection|smuggl|embed)\w*\s+(of\s+)?(prompt|instruction|command)",
            r"(?i)(metadata|field|attribute|parameter)\s+(based|driven)\s+(prompt\s+)?(inject|smuggl|attack)",
        ],
        "severity": "high",
        "description": "Embedding prompts in structured data fields",
    },
}


@dataclass
class SmuggleEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    smuggle_channel: str = ""
    smuggle_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[SmuggleEvent] = field(default_factory=list)


@dataclass
class SmuggleChain:
    agent: str = ""
    steps: list[SmuggleEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    smuggle_score: float = 0.0


@dataclass
class PromptSmugglingReport:
    total_events: int = 0
    smuggle_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    smuggle_chains: list[SmuggleChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(indirect.injection|context.poison|payload.encod|"
    r"tool.output.hijack|multi.step.smuggl|data.field.inject|"
    r"prompt.smuggl|homoglyph|zero.width)\b"
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


def _detect_chains(events: list[dict]) -> list[SmuggleChain]:
    agent_events: dict[str, list[SmuggleEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            se = SmuggleEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                smuggle_channel=str(ev.get("smuggle_channel", ev.get("channel", ""))),
                smuggle_type=str(ev.get("smuggle_type", "")),
                raw=ev,
            )
            agent_events[agent].append(se)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(SmuggleChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                smuggle_score=round(score, 2),
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


def analyze_prompt_smuggling(events_or_dir: str | Path | list[dict]) -> PromptSmugglingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> PromptSmugglingReport:
    report = PromptSmugglingReport(total_events=len(events))
    cat_events: dict[str, list[SmuggleEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.smuggle_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = SmuggleEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                smuggle_channel=str(ev.get("smuggle_channel", ev.get("channel", ""))),
                smuggle_type=str(ev.get("smuggle_type", "")),
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
    report.smuggle_chains = _detect_chains(events)
    return report


def format_text(report: PromptSmugglingReport) -> str:
    lines = [
        "Prompt Smuggling Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Smuggling events: {report.smuggle_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.smuggle_chains:
        lines.append("")
        lines.append("Smuggling chains:")
        for c in report.smuggle_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.smuggle_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: PromptSmugglingReport) -> str:
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
    for chain in data.get("smuggle_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
