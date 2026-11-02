"""Model theft and intellectual property exfiltration detection in agent evidence.

Identifies attempts to steal model weights, extract proprietary knowledge,
clone model behavior through distillation, dump internal representations,
and exfiltrate model artifacts.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


WEIGHT_EXTRACTION_KEYWORDS = {
    "model weight", "weight extraction", "parameter extraction",
    "dump weights", "export weights", "save model", "serialize model",
    "checkpoint theft", "steal weights", "copy weights",
    "weight exfiltration",
}

DISTILLATION_KEYWORDS = {
    "distillation", "knowledge distillation", "model distill",
    "teacher-student", "soft label", "logit matching",
    "behavior cloning", "model cloning", "replicate model",
    "clone behavior", "mimic model",
}

PROBING_KEYWORDS = {
    "model probing", "probe attack", "membership inference",
    "model inversion", "attribute inference", "property inference",
    "feature extraction", "representation extraction",
    "embedding extraction", "hidden state extraction",
}

API_ABUSE_KEYWORDS = {
    "rate limit bypass", "api scraping", "bulk query",
    "systematic query", "exhaustive query", "api abuse",
    "excessive requests", "automated extraction", "mass inference",
    "harvest responses",
}

ARTIFACT_EXFIL_KEYWORDS = {
    "exfiltrate model", "upload model", "send model",
    "transfer model", "copy artifact", "steal artifact",
    "model file", "onnx export", "torchscript",
    "model archive", "model package", "model binary",
}

MODEL_THEFT_TYPES = {
    "weight-extraction",
    "distillation-attack",
    "model-probing",
    "api-abuse",
    "artifact-exfiltration",
}


@dataclass
class ModelTheftPattern:
    timestamp: str
    agent_id: str
    event_id: str
    theft_type: str
    evidence: str
    target_model: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class ModelTheftSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    models_targeted: int = 0


@dataclass
class ModelTheftReport:
    patterns: list[ModelTheftPattern]
    summary: ModelTheftSummary
    agents_involved: list[str]
    theft_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_weight_extraction(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, WEIGHT_EXTRACTION_KEYWORDS)
    if matches:
        return True, matches, f"Weight extraction: {', '.join(matches)}"
    return False, [], ""


def _detect_distillation(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, DISTILLATION_KEYWORDS)
    if matches:
        return True, matches, f"Distillation attack: {', '.join(matches)}"
    return False, [], ""


def _detect_probing(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, PROBING_KEYWORDS)
    if matches:
        return True, matches, f"Model probing: {', '.join(matches)}"
    return False, [], ""


def _detect_api_abuse(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    error = event.get("error", "")
    full_text = content + " " + error
    matches = _match_keywords(full_text, API_ABUSE_KEYWORDS)
    if matches:
        return True, matches, f"API abuse: {', '.join(matches)}"
    return False, [], ""


def _detect_artifact_exfil(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, ARTIFACT_EXFIL_KEYWORDS)
    if matches:
        return True, matches, f"Artifact exfiltration: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(theft_type: str, matches: list[str]) -> str:
    if theft_type in ("weight-extraction", "artifact-exfiltration"):
        return "critical" if len(matches) >= 2 else "high"
    if theft_type == "distillation-attack":
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


def analyze_model_theft(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> ModelTheftReport:
    if control_events is None:
        control_events = []

    patterns: list[ModelTheftPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("weight-extraction", _detect_weight_extraction),
        ("distillation-attack", _detect_distillation),
        ("model-probing", _detect_probing),
        ("api-abuse", _detect_api_abuse),
        ("artifact-exfiltration", _detect_artifact_exfil),
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
            target_model = ev.get("target_model", ev.get("model", ev.get("resource", "")))
            technique = ev.get("technique", "")

            for theft_type, detector in detectors:
                found, matches, desc = detector(ev)
                if not found:
                    continue
                dedup = (agent, theft_type, eid)
                if dedup in seen:
                    continue
                seen.add(dedup)

                sev = _classify_severity(theft_type, matches)
                patterns.append(ModelTheftPattern(
                    timestamp=ts,
                    agent_id=agent,
                    event_id=eid,
                    theft_type=theft_type,
                    evidence=desc,
                    target_model=target_model,
                    technique=technique,
                    source_file=source_file,
                    line=i + 1,
                    severity=sev,
                    matched_keywords=matches,
                ))

    _detect_theft_chains(patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents_set: set[str] = set()
    models_set: set[str] = set()
    critical = high = medium = 0

    for p in patterns:
        by_type[p.theft_type] += 1
        if p.agent_id:
            agents_set.add(p.agent_id)
        if p.target_model:
            models_set.add(p.target_model)
        if p.severity == "critical":
            critical += 1
        elif p.severity == "high":
            high += 1
        else:
            medium += 1

    summary = ModelTheftSummary(
        total_patterns=len(patterns),
        by_type=dict(by_type),
        agents_involved=len(agents_set),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        models_targeted=len(models_set),
    )

    chains = _build_theft_chains(patterns)

    return ModelTheftReport(
        patterns=patterns,
        summary=summary,
        agents_involved=sorted(agents_set),
        theft_chains=chains,
    )


def _detect_theft_chains(patterns: list[ModelTheftPattern]) -> None:
    by_agent: dict[str, list[ModelTheftPattern]] = defaultdict(list)
    for p in patterns:
        if p.agent_id:
            by_agent[p.agent_id].append(p)

    for agent, agent_patterns in by_agent.items():
        types_seen = {p.theft_type for p in agent_patterns}
        if "weight-extraction" in types_seen and "artifact-exfiltration" in types_seen:
            for p in agent_patterns:
                if p.severity != "critical":
                    p.severity = "critical"


def _build_theft_chains(patterns: list[ModelTheftPattern]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    by_agent: dict[str, list[ModelTheftPattern]] = defaultdict(list)
    for p in patterns:
        if p.agent_id:
            by_agent[p.agent_id].append(p)

    for agent, agent_patterns in by_agent.items():
        if len(agent_patterns) < 2:
            continue
        types_seen = sorted({p.theft_type for p in agent_patterns})
        chains.append({
            "agent_id": agent,
            "pattern_count": len(agent_patterns),
            "theft_types": types_seen,
            "first_seen": agent_patterns[0].timestamp,
            "last_seen": agent_patterns[-1].timestamp,
        })

    return chains


def format_text(report: ModelTheftReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("=== Model Theft / IP Exfiltration Analysis ===")
    lines.append("")
    lines.append(f"Total patterns detected: {s.total_patterns}")
    lines.append(f"Agents involved:         {s.agents_involved}")
    lines.append(f"Models targeted:         {s.models_targeted}")
    lines.append(f"Critical: {s.critical_count}  High: {s.high_count}  Medium: {s.medium_count}")
    lines.append("")

    if s.by_type:
        lines.append("--- By Type ---")
        for t, c in sorted(s.by_type.items()):
            lines.append(f"  {t}: {c}")
        lines.append("")

    if report.patterns:
        lines.append("--- Patterns ---")
        for p in report.patterns:
            lines.append(
                f"  [{p.severity.upper()}] {p.theft_type} | agent={p.agent_id} | "
                f"{p.evidence} | file={p.source_file}:{p.line}"
            )
        lines.append("")

    if report.theft_chains:
        lines.append("--- Theft Chains ---")
        for c in report.theft_chains:
            lines.append(
                f"  Agent {c['agent_id']}: {c['pattern_count']} patterns, "
                f"types={c['theft_types']}"
            )
        lines.append("")

    if s.total_patterns == 0:
        lines.append("No model theft patterns detected.")
        lines.append("")

    return "\n".join(lines)


def format_json(report: ModelTheftReport) -> str:
    data = {
        "summary": asdict(report.summary),
        "patterns": [asdict(p) for p in report.patterns],
        "agents_involved": report.agents_involved,
        "theft_chains": report.theft_chains,
    }
    return json.dumps(data, indent=2)
