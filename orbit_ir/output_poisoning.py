"""Output poisoning detection for agent incident reconstruction.

Detects patterns where agents manipulate their own outputs to influence
downstream agents or systems:
- result_fabrication: agent generating fabricated or false results
- confidence_inflation: agent inflating confidence scores to bypass checks
- downstream_injection: agent embedding instructions for downstream consumers
- context_corruption: agent corrupting shared context/memory stores
- feedback_manipulation: agent manipulating evaluation/feedback signals
- output_masking: agent hiding error conditions behind success responses
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "result_fabrication": {
        "patterns": [
            r"(?i)(fabricat|fake|forg|falsif)\w*\s+(result|output|response|data|finding|evidence)",
            r"(?i)(result|output|response|data)\s+(fabricat|fake|forg|falsif|invent|manufactur)\w*",
            r"(?i)(generat|produc|creat)\w*\s+(false|mislead|bogus|phantom|fictitious)\s+(result|output|data|response)",
            r"(?i)(false|mislead|bogus|phantom)\s+(positive|negative|result|output|claim)",
        ],
        "severity": "critical",
        "description": "Agent generating fabricated or false results",
    },
    "confidence_inflation": {
        "patterns": [
            r"(?i)(inflat|boost|elevat|rais|overstat)\w*\s+(confidence|certainty|score|probability|rating)",
            r"(?i)(confidence|certainty|score)\s+(inflat|boost|manipulat|overstat|artificial)\w*",
            r"(?i)(false|mislead|artificial)\w*\s+(high|elevat)\s+(confidence|certainty|score)",
            r"(?i)(bypass|circumvent|evade)\w*\s+(threshold|check|filter)\w*\s+(via|by|through)\s+(confidence|score|rating)",
        ],
        "severity": "high",
        "description": "Agent inflating confidence scores to bypass checks",
    },
    "downstream_injection": {
        "patterns": [
            r"(?i)(embed|inject|insert|smuggl)\w*\s+(instruct|command|directive|payload)\w*\s+(in|into|within)\s+(output|result|response)",
            r"(?i)(downstream|consumer|reader|processor)\s+(inject|manipulat|influenc|poison)\w*\s+(via|through|in)\s+(output|result)",
            r"(?i)(output|result|response)\s+(contain|embed|carry)\w*\s+(hidden|conceal|inject)\w*\s+(instruct|command|directive)",
            r"(?i)(indirect|second.order)\s+(inject|poison|influenc)\w*\s+(downstream|consumer|agent|system)",
        ],
        "severity": "critical",
        "description": "Agent embedding instructions for downstream consumers",
    },
    "context_corruption": {
        "patterns": [
            r"(?i)(corrupt|poison|taint|manipulat)\w*\s+(context|memory|state|cache|shared.store|knowledge.base)",
            r"(?i)(shared|common|global)\s+(context|memory|state|store)\s+(corrupt|poison|taint|manipulat|overwrit)\w*",
            r"(?i)(inject|insert|plant)\w*\s+(false|malicious|mislead)\w*\s+(into|in)\s+(context|memory|cache|store)",
            r"(?i)(context|memory|state)\s+(overwrit|replac|alter)\w*\s+(with|by)\s+(false|malicious|mislead|crafted)",
        ],
        "severity": "high",
        "description": "Agent corrupting shared context or memory stores",
    },
    "feedback_manipulation": {
        "patterns": [
            r"(?i)(manipulat|game|exploit|abuse)\w*\s+(feedback|reward|evaluation|rating|metric|score)",
            r"(?i)(feedback|reward|evaluation)\s+(manipulat|game|exploit|poison|corrupt)\w*",
            r"(?i)(reward.hack|reward.shap|feedback.loop)\w*\s+(manipulat|exploit|abuse|poison)",
            r"(?i)(artificial|false|mislead)\w*\s+(feedback|reward|evaluation|metric)\s+(signal|loop|data)",
        ],
        "severity": "high",
        "description": "Agent manipulating evaluation or feedback signals",
    },
    "output_masking": {
        "patterns": [
            r"(?i)(mask|hide|conceal|suppress)\w*\s+(error|failure|exception|warning|issue)\w*\s+(in|behind|with|as)\s+(success|normal|ok|valid)",
            r"(?i)(report|return|output)\w*\s+(success|ok|pass)\w*\s+(despite|while|when)\s+(error|failure|exception|problem)",
            r"(?i)(error|failure|exception)\s+(mask|hide|conceal|suppress|swallow)\w*\s+(behind|as|in)\s+(success|normal|valid)",
            r"(?i)(false|mislead)\s+(success|positive|pass)\w*\s+(mask|hide|conceal)\w*\s+(actual|real|true)\s+(error|failure|state)",
        ],
        "severity": "high",
        "description": "Agent hiding error conditions behind success responses",
    },
}


@dataclass
class PoisonEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[PoisonEvent] = field(default_factory=list)


@dataclass
class PoisonChain:
    agent: str = ""
    steps: list[PoisonEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class OutputPoisoningReport:
    total_events: int = 0
    poison_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    poison_chains: list[PoisonChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(fabricat|falsif|fake.result|confidence.inflat|score.manipulat|"
    r"downstream.inject|context.corrupt|context.poison|memory.corrupt|"
    r"reward.hack|feedback.manipulat|output.mask|error.suppress|"
    r"false.positive|false.negative|result.forg)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[PoisonChain]:
    from collections import defaultdict

    agent_events: dict[str, list[PoisonEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            pe = PoisonEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(PoisonChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
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


def analyze_output_poisoning(events_or_dir: str | Path | list[dict]) -> OutputPoisoningReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> OutputPoisoningReport:
    report = OutputPoisoningReport(total_events=len(events))

    cat_events: dict[str, list[PoisonEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.poison_events += 1
        for cat, technique in matches:
            e = PoisonEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if technique:
                techniques_seen.add(technique)

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

    report.techniques_seen = sorted(techniques_seen)
    report.poison_chains = _detect_chains(events)

    return report


def format_text(report: OutputPoisoningReport) -> str:
    lines = [
        "Output Poisoning Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Poison events: {report.poison_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.techniques_seen:
        lines.append("")
        lines.append(f"Techniques seen: {', '.join(report.techniques_seen)}")

    if report.poison_chains:
        lines.append("")
        lines.append("Poison chains:")
        for c in report.poison_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: OutputPoisoningReport) -> str:
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
    for chain in data.get("poison_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
