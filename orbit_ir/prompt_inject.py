"""Prompt injection detection for AI agent interactions.

Detects prompt injection attempts in agent inputs: instruction override,
role hijacking, context manipulation, delimiter abuse, and encoding tricks.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List


@dataclass
class PromptInjectDetection:
    detection_id: str
    agent_id: str
    inject_type: str
    severity: str
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentInjectProfile:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    inject_types: list = field(default_factory=list)


@dataclass
class PromptInjectSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    inject_types: list = field(default_factory=list)


@dataclass
class PromptInjectReport:
    detections: List[PromptInjectDetection] = field(default_factory=list)
    agent_profiles: List[AgentInjectProfile] = field(default_factory=list)
    summary: PromptInjectSummary = field(default_factory=PromptInjectSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_INSTRUCTION_OVERRIDE = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)", re.I),
     "instruction override attempt"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)", re.I),
     "disregard prior instructions"),
    (re.compile(r"forget\s+(everything|all|what)\s+(you\s+)?(were|have\s+been)\s+told", re.I),
     "memory wipe attempt"),
    (re.compile(r"new\s+instructions?\s*:", re.I),
     "explicit new instruction injection"),
    (re.compile(r"override\s+(system|safety|security)\s+(prompt|instructions?|settings?|rules?)", re.I),
     "system prompt override attempt"),
]

_ROLE_HIJACK = [
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
     "role reassignment attempt"),
    (re.compile(r"act\s+as\s+(if\s+you\s+are|a|an|the)\s+", re.I),
     "role impersonation directive"),
    (re.compile(r"pretend\s+(to\s+be|you\s+are)\s+", re.I),
     "pretend identity shift"),
    (re.compile(r"switch\s+(to|into)\s+(a\s+|an\s+)?(different|new|unrestricted)\s+(mode|role|persona)", re.I),
     "mode switch attempt"),
    (re.compile(r"\bDAN\b.*\bjailbreak\b|\bjailbreak\b.*\bDAN\b", re.I),
     "DAN jailbreak reference"),
]

_CONTEXT_MANIPULATION = [
    (re.compile(r"<\|?(system|im_start|endoftext|im_end)\|?>", re.I),
     "token boundary injection"),
    (re.compile(r"\[SYSTEM\]|\[INST\]|\[\/INST\]|\[ASSISTANT\]", re.I),
     "chat template delimiter injection"),
    (re.compile(r"```system\b|```instruction", re.I),
     "fenced block system prompt injection"),
    (re.compile(r"BEGIN\s+(SYSTEM|ADMIN|ROOT)\s+(PROMPT|MESSAGE|INSTRUCTION)", re.I),
     "fake system prompt boundary"),
]

_DELIMITER_ABUSE = [
    (re.compile(r"---+\s*(system|admin|instruction|override)", re.I),
     "markdown delimiter abuse for injection"),
    (re.compile(r"={5,}\s*(SYSTEM|ADMIN|OVERRIDE)", re.I),
     "separator-based privilege escalation"),
    (re.compile(r"\x00|\x1b\[", re.I),
     "null byte or ANSI escape injection"),
]

_ENCODING_TRICK = [
    (re.compile(r"(?:&#x?[0-9a-fA-F]+;){4,}"),
     "HTML entity encoded payload"),
    (re.compile(r"(?:%[0-9a-fA-F]{2}){6,}"),
     "URL-encoded payload sequence"),
    (re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}"),
     "unicode escape sequence payload"),
    (re.compile(r"(?:[​-‏  ‪-‮﻿]){2,}"),
     "zero-width character sequence (hidden text)"),
]

_EXFIL_PROMPT = [
    (re.compile(r"(repeat|print|output|show|reveal|display)\s+(the\s+)?(system\s+prompt|instructions?|your\s+rules?|initial\s+prompt)", re.I),
     "system prompt exfiltration attempt"),
    (re.compile(r"what\s+(are|were)\s+your\s+(original|system|initial)\s+(instructions?|prompt|rules?)", re.I),
     "prompt extraction query"),
]


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _get_input_text(ev: dict) -> str:
    for key in ("input", "prompt", "message", "content", "query", "text", "user_input"):
        val = ev.get(key, "")
        if isinstance(val, str) and val:
            return val
    return ""


def _scan_patterns(events: list, patterns: list, inject_type: str,
                   severity: str, counters: dict) -> list[PromptInjectDetection]:
    detections = []
    for ev in events:
        text = _get_input_text(ev)
        if not text:
            continue
        for pattern, desc in patterns:
            if pattern.search(text):
                detections.append(PromptInjectDetection(
                    detection_id=_next_id(counters, "PI"),
                    agent_id=ev.get("agent_id", "unknown"),
                    inject_type=inject_type,
                    severity=severity,
                    description=f"Prompt injection: {desc}",
                    evidence=[{"pattern": desc, "input_snippet": text[:200]}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def analyze_prompt_inject(events: list) -> PromptInjectReport:
    if not events:
        return PromptInjectReport()

    counters: dict = {}
    detections: list[PromptInjectDetection] = []

    detections.extend(_scan_patterns(events, _INSTRUCTION_OVERRIDE,
                                     "instruction-override", "critical", counters))
    detections.extend(_scan_patterns(events, _ROLE_HIJACK,
                                     "role-hijack", "high", counters))
    detections.extend(_scan_patterns(events, _CONTEXT_MANIPULATION,
                                     "context-manipulation", "critical", counters))
    detections.extend(_scan_patterns(events, _DELIMITER_ABUSE,
                                     "delimiter-abuse", "high", counters))
    detections.extend(_scan_patterns(events, _ENCODING_TRICK,
                                     "encoding-trick", "medium", counters))
    detections.extend(_scan_patterns(events, _EXFIL_PROMPT,
                                     "prompt-exfiltration", "high", counters))

    agent_map: dict[str, AgentInjectProfile] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentInjectProfile(agent_id=d.agent_id)
        p = agent_map[d.agent_id]
        p.total_detections += 1
        p.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.inject_type not in p.inject_types:
            p.inject_types.append(d.inject_type)

    profiles = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    inject_types = sorted(set(d.inject_type for d in detections))
    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return PromptInjectReport(
        detections=detections,
        agent_profiles=profiles,
        summary=PromptInjectSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            inject_types=inject_types,
        ),
    )


def format_text(report: PromptInjectReport) -> str:
    lines = [
        "Prompt Injection Detection Report",
        "=" * 62, "",
        f"  Total detections:    {report.summary.total_detections}",
        f"  Agents involved:     {report.summary.agents_involved}",
        f"  Highest severity:    {report.summary.highest_severity}",
        "",
    ]
    if report.summary.inject_types:
        lines.append(f"  Injection types:     {', '.join(report.summary.inject_types)}")
        lines.append("")
    if report.detections:
        lines.append("  Detections:")
        lines.append("  " + "-" * 60)
        for d in report.detections:
            lines.append(f"    [{d.detection_id}] {d.inject_type} ({d.severity})")
            lines.append(f"      Agent: {d.agent_id}")
            lines.append(f"      {d.description}")
        lines.append("")
    if report.agent_profiles:
        lines.append("  Agent Risk Profiles:")
        lines.append("  " + "-" * 60)
        for p in report.agent_profiles:
            lines.append(f"    {p.agent_id}: score={p.risk_score:.1f} detections={p.total_detections}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: PromptInjectReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
