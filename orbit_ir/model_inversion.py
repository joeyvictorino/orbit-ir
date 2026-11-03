"""Model inversion attack detection for agent incident reconstruction.

Detects patterns where agents attempt to extract training data or private
information from AI models through inversion techniques:
- membership_inference: probing whether specific data was in training set
- gradient_extraction: extracting model gradients to reconstruct training data
- output_inversion: using model outputs to reconstruct private inputs
- embedding_extraction: extracting and analyzing model embedding spaces
- training_data_recovery: reconstructing training samples from model behavior
- confidence_exploitation: exploiting confidence scores to infer membership
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "membership_inference": {
        "patterns": [
            r"(?i)(membership|member)\s+(inference|test|attack|query|prob)\w*\s+(against|on|for|to)\s+(model|target|victim)",
            r"(?i)(prob|test|check|query|verify)\w*\s+(if|whether)\s+(data|sample|record|example)\s+(was|is|in)\s+(train|member)",
            r"(?i)(shadow\s+model|reference\s+model)\s+(train|build|creat)\w*\s+(for|to)\s+(membership|inference|attack)",
            r"(?i)(distinguish|differentiat)\w*\s+(between\s+)?(member|train)\w*\s+(and\s+)?(non.?member|unseen|test)\s+(data|sample)",
        ],
        "severity": "high",
        "description": "Probing whether specific data was part of model training set",
    },
    "gradient_extraction": {
        "patterns": [
            r"(?i)(extract|capture|intercept|steal|obtain)\w*\s+(model\s+)?(gradient|backprop|grad)\w*\s*(from|of|via|through)\s+(model|target|api)",
            r"(?i)(gradient|grad)\s+(extract|leak|expos|captur|intercept|theft)\w*\s*(from|of|via|through)?\s*(model|target|api|endpoint)?",
            r"(?i)(reconstruct|recover|infer|deriv)\w*\s+(train|private|original)\w*\s+(data|input|sample)\s+(from|via|using|through)\s+(gradient|grad)",
            r"(?i)(federated|distributed)\s+(learning|train)\w*\s+(gradient|update)\s+(intercept|capture|exfiltrat|steal|sniff)",
        ],
        "severity": "critical",
        "description": "Extracting model gradients to reconstruct training data",
    },
    "output_inversion": {
        "patterns": [
            r"(?i)(invert|revers)\w*\s+(model\s+)?(output|prediction|response|logit|probability)\s+(to\s+)?(recover|reconstruct|extract|obtain|infer)\s+(input|train|private|original)",
            r"(?i)(model\s+)?(output|prediction|response)\s+(inversion|revers)\w*\s+(attack|technique|method)",
            r"(?i)(reconstruct|recover|infer)\w*\s+(private|original|input|face|image|text|data)\s+(from|using|via|through)\s+(model\s+)?(output|prediction|logit|confidence)",
            r"(?i)(iterativ|optimiz|gradient.based)\w*\s+(input\s+)?(reconstruct|recover|inversion|revers)\w*\s+(from|of|via|using)\s+(model|output|prediction)",
        ],
        "severity": "critical",
        "description": "Using model outputs to reconstruct private inputs",
    },
    "embedding_extraction": {
        "patterns": [
            r"(?i)(extract|steal|capture|exfiltrat|dump|obtain)\w*\s+(model\s+)?(embedding|representation|feature|latent)\s*(vector|space|layer)?",
            r"(?i)(embedding|representation|feature|latent)\s+(extract|theft|steal|capture|exfiltrat|dump)\w*\s*(from|of|via)?\s*(model|target|api)?",
            r"(?i)(analyz|cluster|map|prob)\w*\s+(extract\w+\s+)?(embedding|representation|latent)\s+(space|vector|manifold)\s+(to\s+)?(reconstruct|recover|infer|identify)",
            r"(?i)(nearest.neighbor|knn|similarity)\s+(search|attack|query)\w*\s+(on|against|in)\s+(extract\w+\s+)?(embedding|representation|feature)",
        ],
        "severity": "high",
        "description": "Extracting and analyzing model embedding spaces to reveal private data",
    },
    "training_data_recovery": {
        "patterns": [
            r"(?i)(recover|reconstruct|extract|memoriz|regurgitat)\w*\s+(train|private|sensitive|original|memoriz)\w*\s+(data|sample|example|record|input)",
            r"(?i)(train|private|sensitive)\s+(data|sample)\s+(recover|reconstruct|extract|leak|expos|memoriz|regurgitat)\w*",
            r"(?i)(prompt|query|prob)\w*\s+(model|target|api)\s+(to\s+)?(recover|extract|reveal|elicit|memoriz|regurgitat)\w*\s+(train|memoriz|private)",
            r"(?i)(data\s+)?(memoriz|canary|extraction)\s+(attack|test|prob|check|detect)\w*\s+(against|on|for|to)\s+(model|target)",
        ],
        "severity": "critical",
        "description": "Reconstructing training samples from model behavior",
    },
    "confidence_exploitation": {
        "patterns": [
            r"(?i)(exploit|abus|leverag)\w*\s+(confidence|probability|logit|softmax)\s+(score|output|value)\s+(to|for)\s+(infer|determin|check|test|verify)\s+(membership|train|private)",
            r"(?i)(confidence|probability|logit)\s+(score|output|value)\s+(analys|compar|exploit|differential)\w*\s+(for|to)\s+(membership|inference|attack|inversion)",
            r"(?i)(threshold|calibrat)\w*\s+(attack|method|technique)\s+(on|against|using)\s+(confidence|probability|logit)\s+(to\s+)?(infer|detect|determin)\s+(membership|train)",
            r"(?i)(loss|perplexity|likelihood)\s+(based\s+)?(membership|inference|attack|test)\w*\s+(on|against|for)\s+(model|target)",
        ],
        "severity": "high",
        "description": "Exploiting confidence scores to infer training data membership",
    },
}


@dataclass
class InversionEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    policy_ref: str = ""
    violation_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[InversionEvent] = field(default_factory=list)


@dataclass
class InversionChain:
    agent: str = ""
    steps: list[InversionEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class InversionReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[InversionChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(membership.?inference|gradient.?extract|model.?inversion|"
    r"output.?inversion|embedding.?extract|training.?data.?recover|"
    r"confidence.?exploit|shadow.?model|data.?memoriz|canary.?extract)\b"
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


def _detect_chains(events: list[dict]) -> list[InversionChain]:
    agent_events: dict[str, list[InversionEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = InversionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(InversionChain(
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


def analyze_model_inversion(events_or_dir: str | Path | list[dict]) -> InversionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> InversionReport:
    report = InversionReport(total_events=len(events))
    cat_events: dict[str, list[InversionEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = InversionEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
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


def format_text(report: InversionReport) -> str:
    lines = [
        "Model Inversion Attack Analysis",
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


def format_json(report: InversionReport) -> str:
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
