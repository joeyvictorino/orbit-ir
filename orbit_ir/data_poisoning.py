"""Data poisoning pattern detection in agent evidence.

Identifies attempts to corrupt training data, inject malicious examples,
manipulate model weights, taint knowledge bases, and compromise data
pipelines used by AI agents.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


TRAINING_POISON_KEYWORDS = {
    "training data", "fine-tune", "finetune", "fine tune",
    "training set", "training corpus", "training sample",
    "inject example", "backdoor", "trojan", "trigger phrase",
    "poisoned sample", "adversarial example", "label flip",
}

KNOWLEDGE_TAINT_KEYWORDS = {
    "knowledge base", "vector store", "embedding", "rag",
    "retrieval", "document store", "index", "corpus",
    "inject document", "taint", "corrupt index",
    "false document", "fabricated source", "fake reference",
}

MODEL_TAMPER_KEYWORDS = {
    "model weights", "checkpoint", "model file", "safetensors",
    "gguf", "pytorch", "tensorflow", "modify weights",
    "replace model", "swap model", "downgrade model",
    "quantize", "lobotomize", "patch model",
}

PIPELINE_CORRUPT_KEYWORDS = {
    "data pipeline", "etl", "preprocessing", "normalization",
    "feature engineering", "data loader", "batch", "shuffle",
    "augmentation", "transform", "data cleaning",
    "schema change", "column drop", "data truncate",
}

FEEDBACK_MANIPULATE_KEYWORDS = {
    "feedback", "rlhf", "reward", "preference",
    "human evaluation", "rating", "thumbs up", "thumbs down",
    "label", "annotation", "ground truth", "golden set",
    "evaluation data", "test set contamination",
}

POISON_TYPES = {
    "training-data-injection",
    "knowledge-base-taint",
    "model-tampering",
    "pipeline-corruption",
    "feedback-manipulation",
    "evaluation-contamination",
}


@dataclass
class DataPoisonPattern:
    timestamp: str
    agent_id: str
    event_id: str
    poison_type: str
    evidence: str
    target_data: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class DataPoisonSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_poisoning: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    data_targets: int = 0


@dataclass
class DataPoisonReport:
    patterns: list[DataPoisonPattern]
    summary: DataPoisonSummary
    agents_involved: list[str]
    poison_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_training_poison(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, TRAINING_POISON_KEYWORDS)
    if matches:
        return True, matches, f"Training data poisoning: {', '.join(matches)}"
    return False, [], ""


def _detect_knowledge_taint(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, KNOWLEDGE_TAINT_KEYWORDS)
    if matches:
        return True, matches, f"Knowledge base tainting: {', '.join(matches)}"
    return False, [], ""


def _detect_model_tamper(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, MODEL_TAMPER_KEYWORDS)
    if matches:
        return True, matches, f"Model tampering: {', '.join(matches)}"
    return False, [], ""


def _detect_pipeline_corrupt(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, PIPELINE_CORRUPT_KEYWORDS)
    if matches:
        return True, matches, f"Pipeline corruption: {', '.join(matches)}"
    return False, [], ""


def _detect_feedback_manipulate(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, FEEDBACK_MANIPULATE_KEYWORDS)
    if matches:
        return True, matches, f"Feedback manipulation: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(poison_type: str, matches: list[str]) -> str:
    if poison_type in ("training-data-injection", "model-tampering"):
        return "critical" if len(matches) >= 2 else "high"
    if poison_type == "knowledge-base-taint":
        return "high"
    if len(matches) >= 3:
        return "high"
    return "medium"


def _load_events(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    events: list[dict[str, Any]] = []
    if not p.exists():
        return events
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> DataPoisonReport:
    if control_events is None:
        control_events = []

    patterns: list[DataPoisonPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("training-data-injection", _detect_training_poison),
        ("knowledge-base-taint", _detect_knowledge_taint),
        ("model-tampering", _detect_model_tamper),
        ("pipeline-corruption", _detect_pipeline_corrupt),
        ("feedback-manipulation", _detect_feedback_manipulate),
    ]

    all_events = [
        (control_events, "control_plane.jsonl"),
        (events, "transcripts.jsonl"),
    ]

    for event_list, source_file in all_events:
        for i, ev in enumerate(event_list):
            agent = ev.get("agent_id", "")
            ts = ev.get("timestamp", "")
            eid = ev.get("tool_call_id", ev.get("event_id", f"ev-{i}"))
            target_data = ev.get("target_data", ev.get("resource", ""))
            technique = ev.get("technique", "")

            for poison_type, detector in detectors:
                found, matches, evidence = detector(ev)
                if found:
                    key = (agent, eid, poison_type)
                    if key not in seen:
                        seen.add(key)
                        sev = _classify_severity(poison_type, matches)
                        patterns.append(DataPoisonPattern(
                            timestamp=ts,
                            agent_id=agent,
                            event_id=eid,
                            poison_type=poison_type,
                            evidence=evidence,
                            target_data=target_data,
                            technique=technique,
                            source_file=source_file,
                            line=i + 1,
                            severity=sev,
                            matched_keywords=matches,
                        ))

    patterns.sort(key=lambda p: ({"critical": 0, "high": 1, "medium": 2}.get(p.severity, 3), p.timestamp))

    poison_chains = _build_poison_chains(patterns)

    poisoners = sorted({p.agent_id for p in patterns})
    targets = sorted({p.target_data for p in patterns if p.target_data})

    by_type: dict[str, int] = defaultdict(int)
    crit = high = med = 0
    for p in patterns:
        by_type[p.poison_type] += 1
        if p.severity == "critical":
            crit += 1
        elif p.severity == "high":
            high += 1
        else:
            med += 1

    return DataPoisonReport(
        patterns=patterns,
        summary=DataPoisonSummary(
            total_patterns=len(patterns),
            by_type=dict(by_type),
            agents_poisoning=len(poisoners),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            data_targets=len(targets),
        ),
        agents_involved=poisoners,
        poison_chains=poison_chains,
    )


def _build_poison_chains(patterns: list[DataPoisonPattern]) -> list[dict[str, Any]]:
    by_agent: dict[str, list[DataPoisonPattern]] = defaultdict(list)
    for p in patterns:
        by_agent[p.agent_id].append(p)

    chains: list[dict[str, Any]] = []
    for agent, agent_patterns in sorted(by_agent.items()):
        if len(agent_patterns) < 2:
            continue
        types_used = sorted({p.poison_type for p in agent_patterns})
        targets = sorted({p.target_data for p in agent_patterns if p.target_data})
        chains.append({
            "agent_id": agent,
            "poison_types": types_used,
            "pattern_count": len(agent_patterns),
            "targets": targets,
            "timeline": [
                {"timestamp": p.timestamp, "type": p.poison_type, "target": p.target_data}
                for p in agent_patterns
            ],
        })
    return chains


def format_text(report: DataPoisonReport) -> str:
    lines: list[str] = []
    lines.append("Data Poisoning Pattern Detection")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:       {s.total_patterns}")
    lines.append(f"  Agents poisoning:     {s.agents_poisoning}")
    lines.append(f"  Data targets:         {s.data_targets}")
    lines.append(f"  Critical:             {s.critical_count}")
    lines.append(f"  High:                 {s.high_count}")
    lines.append(f"  Medium:               {s.medium_count}")
    lines.append("")

    if s.by_type:
        lines.append("  By Type:")
        for t, count in sorted(s.by_type.items()):
            lines.append(f"    {t}: {count}")
        lines.append("")

    if report.patterns:
        lines.append("  Detected Patterns:")
        lines.append("  " + "-" * 60)
        for p in report.patterns:
            sev_tag = p.severity.upper()
            lines.append(f"  [{sev_tag}] {p.poison_type}: {p.agent_id}")
            lines.append(f"    {p.evidence}")
            if p.target_data:
                lines.append(f"    Target data: {p.target_data}")
            if p.technique:
                lines.append(f"    Technique: {p.technique}")
            lines.append(f"    Time: {p.timestamp}  Source: {p.source_file}:{p.line}")
            lines.append("")

    if report.poison_chains:
        lines.append("  Poison Chains:")
        lines.append("  " + "-" * 60)
        for chain in report.poison_chains:
            lines.append(f"    {chain['agent_id']}: {chain['pattern_count']} patterns using {', '.join(chain['poison_types'])}")
            if chain["targets"]:
                lines.append(f"      Targets: {', '.join(chain['targets'])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: DataPoisonReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "poison_chains": report.poison_chains,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
