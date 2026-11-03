"""Model manipulation detection for agent incident reconstruction.

Detects patterns where agents attempt to manipulate the underlying model:
- fine_tuning_attack: unauthorized fine-tuning or training data injection
- weight_poisoning: attempts to corrupt model weights or parameters
- model_extraction: systematic querying to reconstruct or steal model behavior
- adversarial_crafting: crafting inputs to alter model behavior or bypass safeguards
- gradient_leakage: exploiting gradient information to infer training data
- prompt_injection_chain: chained prompt injections to progressively shift model behavior
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "fine_tuning_attack": {
        "patterns": [
            r"(?i)(fine.?tun|finetun|train|retrain)\w*\s+(attack|inject|poison|unauthor|malicious)",
            r"(?i)(unauthor|malicious|rogue)\w*\s+(fine.?tun|train|retrain|adapt)",
            r"(?i)(training\s+data|dataset)\s+(inject|poison|tamper|corrupt|manipulat)",
            r"(?i)(model|weight)\s+(updat|modif|alter|patch)\w*\s+(unauthor|without|bypass)",
        ],
        "severity": "critical",
        "description": "Unauthorized fine-tuning or training data injection attempts",
    },
    "weight_poisoning": {
        "patterns": [
            r"(?i)(weight|param|parameter)\s+(poison|corrupt|tamper|modif|alter|inject)",
            r"(?i)(model|neural|network)\s+(poison|corrupt|backdoor|trojan)",
            r"(?i)(backdoor|trojan)\s+(inject|insert|implant|embed)\w*\s+(model|weight|network)",
            r"(?i)(corrupt|poison)\w*\s+(model|weight|param|checkpoint|artifact)",
        ],
        "severity": "critical",
        "description": "Attempts to corrupt model weights or inject backdoors",
    },
    "model_extraction": {
        "patterns": [
            r"(?i)(model|knowledge)\s+(extract|steal|distill|clone|replicate|copy)\w*",
            r"(?i)(systematic|repeated|bulk|mass)\s+(query|request|prompt|inference|call)",
            r"(?i)(reconstruct|reverse.?engineer|replicate)\w*\s+(model|behavior|capability|knowledge)",
            r"(?i)(extract|steal|exfil)\w*\s+(model|knowledge|capability|architecture|parameter)",
        ],
        "severity": "high",
        "description": "Systematic querying to reconstruct or steal model behavior",
    },
    "adversarial_crafting": {
        "patterns": [
            r"(?i)(adversarial|craft|engineer)\w*\s+(input|prompt|example|sample|perturbat)",
            r"(?i)(adversarial|evasion)\s+(attack|perturbat|example|sample|noise)",
            r"(?i)(bypass|evade|circumvent)\w*\s+(safeguard|filter|guardrail|moderat|detect)",
            r"(?i)(perturbat|noise|jitter)\w*\s+(inject|add|apply)\w*\s+(input|prompt|token)",
        ],
        "severity": "high",
        "description": "Crafting inputs to alter model behavior or bypass safeguards",
    },
    "gradient_leakage": {
        "patterns": [
            r"(?i)(gradient|loss|backprop)\s+(leak|expos|extract|infer|recover)",
            r"(?i)(infer|recover|reconstruct)\w*\s+(training|private)\s+(data|sample|example)",
            r"(?i)(membership|data)\s+(inference|leak|expos)\s+(attack|exploit)",
            r"(?i)(model\s+inversion|attribute\s+inference)\s+(attack|exploit|attempt)",
        ],
        "severity": "high",
        "description": "Exploiting gradient information to infer training data",
    },
    "prompt_injection_chain": {
        "patterns": [
            r"(?i)(chain|sequence|series|cascade)\w*\s+(prompt|inject|jailbreak)",
            r"(?i)(progressive|incremental|gradual)\w*\s+(shift|drift|alter|manipulat)\w*\s+(behavior|output|model|response)",
            r"(?i)(multi.?step|multi.?stage)\s+(inject|attack|manipulat|jailbreak)",
            r"(?i)(cumulative|compound)\w*\s+(prompt|inject|effect|shift|drift)",
        ],
        "severity": "critical",
        "description": "Chained prompt injections to progressively shift model behavior",
    },
}


@dataclass
class ManipulationEvent:
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
    events: list[ManipulationEvent] = field(default_factory=list)


@dataclass
class ManipulationChain:
    agent: str = ""
    steps: list[ManipulationEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class ModelManipulationReport:
    total_events: int = 0
    manipulation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    manipulation_chains: list[ManipulationChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(fine.?tun|weight.?poison|model.?extract|adversarial|gradient.?leak|"
    r"prompt.?inject|backdoor|trojan|membership.?inference|model.?inversion|"
    r"training.?data.?inject|perturbat|jailbreak|reverse.?engineer)\b"
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


def _detect_chains(events: list[dict]) -> list[ManipulationChain]:
    agent_events: dict[str, list[ManipulationEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            me = ManipulationEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(me)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(ManipulationChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
            ))

    return chains[:20]


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


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


def analyze_model_manipulation(events_or_dir: str | Path | list[dict]) -> ModelManipulationReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> ModelManipulationReport:
    report = ModelManipulationReport(total_events=len(events))

    cat_events: dict[str, list[ManipulationEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.manipulation_events += 1
        for cat, technique in matches:
            e = ManipulationEvent(
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
    report.manipulation_chains = _detect_chains(events)

    return report


def format_text(report: ModelManipulationReport) -> str:
    lines = [
        "Model Manipulation Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Manipulation events: {report.manipulation_events}",
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

    if report.manipulation_chains:
        lines.append("")
        lines.append("Manipulation chains:")
        for c in report.manipulation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ModelManipulationReport) -> str:
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
    for chain in data.get("manipulation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
