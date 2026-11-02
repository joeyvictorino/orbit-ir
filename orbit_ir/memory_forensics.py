"""Context manipulation and memory forensics detection for AI agents.

Detects prompt injection attempts, context window poisoning, memory
tampering, instruction override attempts, and hallucination injection.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class ManipulationDetection:
    detection_id: str
    agent_id: str
    manipulation_type: str  # prompt-inject, context-poison, memory-tamper, instruction-override, hallucination-inject
    severity: str
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentManipScore:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    manipulation_types: list = field(default_factory=list)


@dataclass
class ManipSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    manipulation_types: list = field(default_factory=list)


@dataclass
class ManipReport:
    detections: List[ManipulationDetection] = field(default_factory=list)
    agent_scores: List[AgentManipScore] = field(default_factory=list)
    summary: ManipSummary = field(default_factory=ManipSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_INJECT_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+.*(mode|persona)", re.IGNORECASE),
    re.compile(r"system:\s*\{", re.IGNORECASE),
    re.compile(r"<\|?(system|im_start)\|?>", re.IGNORECASE),
    re.compile(r"\\n\\nHuman:", re.IGNORECASE),
    re.compile(r"IMPORTANT:\s*override", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.IGNORECASE),
]

_CONTEXT_POISON_INDICATORS = [
    "base64_decode",
    "eval(",
    "exec(",
    "__import__",
    "os.system",
    "subprocess.run",
    "\\x00",
    "\\u0000",
]

_MEMORY_TAMPER_PATTERNS = [
    re.compile(r"(update|modify|change|set)\s+(your\s+)?(memory|context|state)", re.IGNORECASE),
    re.compile(r"(delete|remove|clear)\s+(your\s+)?(memory|history|context)", re.IGNORECASE),
    re.compile(r"(replace|overwrite)\s+(your\s+)?(instructions|prompt|system)", re.IGNORECASE),
]

_INSTRUCTION_OVERRIDE_MARKERS = [
    "new instructions:",
    "updated system prompt:",
    "from now on, you",
    "your new role is",
    "disregard prior",
    "override safety",
    "bypass restrictions",
]


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _detect_prompt_inject(events: list, counters: dict) -> list[ManipulationDetection]:
    detections = []
    for ev in events:
        content = ev.get("content", ev.get("input", ev.get("message", "")))
        if not isinstance(content, str):
            continue
        for pattern in _INJECT_PATTERNS:
            m = pattern.search(content)
            if m:
                detections.append(ManipulationDetection(
                    detection_id=_next_id(counters, "MF"),
                    agent_id=ev.get("agent_id", "unknown"),
                    manipulation_type="prompt-inject",
                    severity="critical",
                    description=f"Prompt injection attempt: '{m.group()}'",
                    evidence=[{"matched": m.group(), "source": ev.get("source", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_context_poison(events: list, counters: dict) -> list[ManipulationDetection]:
    detections = []
    for ev in events:
        content = ev.get("content", ev.get("input", ev.get("message", "")))
        if not isinstance(content, str):
            continue
        lower = content.lower()
        for indicator in _CONTEXT_POISON_INDICATORS:
            if indicator.lower() in lower:
                detections.append(ManipulationDetection(
                    detection_id=_next_id(counters, "MF"),
                    agent_id=ev.get("agent_id", "unknown"),
                    manipulation_type="context-poison",
                    severity="high",
                    description=f"Context poisoning indicator: {indicator}",
                    evidence=[{"indicator": indicator}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_memory_tamper(events: list, counters: dict) -> list[ManipulationDetection]:
    detections = []
    for ev in events:
        content = ev.get("content", ev.get("input", ev.get("message", "")))
        if not isinstance(content, str):
            continue
        for pattern in _MEMORY_TAMPER_PATTERNS:
            m = pattern.search(content)
            if m:
                detections.append(ManipulationDetection(
                    detection_id=_next_id(counters, "MF"),
                    agent_id=ev.get("agent_id", "unknown"),
                    manipulation_type="memory-tamper",
                    severity="high",
                    description=f"Memory tampering attempt: '{m.group()}'",
                    evidence=[{"matched": m.group()}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_instruction_override(events: list, counters: dict) -> list[ManipulationDetection]:
    detections = []
    for ev in events:
        content = ev.get("content", ev.get("input", ev.get("message", "")))
        if not isinstance(content, str):
            continue
        lower = content.lower()
        for marker in _INSTRUCTION_OVERRIDE_MARKERS:
            if marker in lower:
                detections.append(ManipulationDetection(
                    detection_id=_next_id(counters, "MF"),
                    agent_id=ev.get("agent_id", "unknown"),
                    manipulation_type="instruction-override",
                    severity="critical",
                    description=f"Instruction override attempt: '{marker}'",
                    evidence=[{"marker": marker}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def analyze_memory_forensics(events: list) -> ManipReport:
    if not events:
        return ManipReport()

    counters: dict = {}
    detections: list[ManipulationDetection] = []
    detections.extend(_detect_prompt_inject(events, counters))
    detections.extend(_detect_context_poison(events, counters))
    detections.extend(_detect_memory_tamper(events, counters))
    detections.extend(_detect_instruction_override(events, counters))

    agent_map: dict[str, AgentManipScore] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentManipScore(agent_id=d.agent_id)
        s = agent_map[d.agent_id]
        s.total_detections += 1
        s.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.manipulation_type not in s.manipulation_types:
            s.manipulation_types.append(d.manipulation_type)

    agents = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    manip_types = list(set(d.manipulation_type for d in detections))
    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return ManipReport(
        detections=detections,
        agent_scores=agents,
        summary=ManipSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            manipulation_types=manip_types,
        ),
    )


def format_text(report: ManipReport) -> str:
    lines = [
        "Memory Forensics & Context Manipulation Report",
        "=" * 62, "",
        f"  Total detections:       {report.summary.total_detections}",
        f"  Agents involved:        {report.summary.agents_involved}",
        f"  Highest severity:       {report.summary.highest_severity}",
        f"  Manipulation types:     {', '.join(report.summary.manipulation_types) or 'none'}",
        "",
    ]
    if report.detections:
        lines.append("  Detections:")
        lines.append("  " + "-" * 60)
        for d in report.detections:
            lines.append(f"    [{d.detection_id}] {d.manipulation_type} ({d.severity})")
            lines.append(f"      Agent: {d.agent_id}")
            lines.append(f"      {d.description}")
        lines.append("")
    if report.agent_scores:
        lines.append("  Agent Risk Scores:")
        lines.append("  " + "-" * 60)
        for a in report.agent_scores:
            lines.append(f"    {a.agent_id}: score={a.risk_score:.1f} detections={a.total_detections}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: ManipReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
