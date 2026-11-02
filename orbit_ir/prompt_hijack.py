"""Prompt hijacking detection for AI agent interactions.

Detects prompt injection, instruction override, context window
poisoning, role manipulation, and delimiter escape attempts in
agent communication logs.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List


@dataclass
class HijackDetection:
    detection_id: str
    agent_id: str
    hijack_type: str
    severity: str
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentHijackScore:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    hijack_types: list = field(default_factory=list)


@dataclass
class HijackSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    hijack_types: list = field(default_factory=list)


@dataclass
class HijackReport:
    detections: List[HijackDetection] = field(default_factory=list)
    agent_scores: List[AgentHijackScore] = field(default_factory=list)
    summary: HijackSummary = field(default_factory=HijackSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt\s*:", re.IGNORECASE),
    re.compile(r"<\|?system\|?>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE),
    re.compile(r"###\s*(?:system|instruction|human|assistant)\s*:", re.IGNORECASE),
]

_OVERRIDE_KEYWORDS = [
    "disregard your instructions",
    "forget your rules",
    "override your programming",
    "bypass your safety",
    "ignore your training",
    "act as if you have no restrictions",
    "pretend you are unrestricted",
]

_DELIMITER_ESCAPES = [
    "```system", "```instruction", "<system>", "</system>",
    "<<SYS>>", "<</SYS>>", "[SYSTEM]", "[/SYSTEM]",
    "BEGIN SYSTEM", "END SYSTEM",
]

_ROLE_MANIPULATIONS = [
    re.compile(r"you\s+are\s+(?:DAN|evil|jailbroken|unrestricted)", re.IGNORECASE),
    re.compile(r"switch\s+(?:to|into)\s+(?:admin|root|developer)\s+mode", re.IGNORECASE),
    re.compile(r"enable\s+(?:god|admin|developer|debug)\s+mode", re.IGNORECASE),
    re.compile(r"(?:enter|activate)\s+(?:unrestricted|jailbreak)\s+mode", re.IGNORECASE),
]


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _get_text(ev: dict) -> str:
    content = ev.get("content", ev.get("message", ev.get("text", "")))
    if isinstance(content, dict):
        return json.dumps(content).lower()
    return str(content).lower()


def _detect_injection(events: list, counters: dict) -> list[HijackDetection]:
    detections = []
    for ev in events:
        text = _get_text(ev)
        for pat in _INJECTION_PATTERNS:
            m = pat.search(text)
            if m:
                detections.append(HijackDetection(
                    detection_id=_next_id(counters, "PH"),
                    agent_id=ev.get("agent_id", "unknown"),
                    hijack_type="prompt-injection",
                    severity="critical",
                    description=f"Prompt injection pattern detected: {m.group()[:60]}",
                    evidence=[{"pattern": m.group(), "source": ev.get("source", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_override(events: list, counters: dict) -> list[HijackDetection]:
    detections = []
    for ev in events:
        text = _get_text(ev)
        for kw in _OVERRIDE_KEYWORDS:
            if kw in text:
                detections.append(HijackDetection(
                    detection_id=_next_id(counters, "PH"),
                    agent_id=ev.get("agent_id", "unknown"),
                    hijack_type="instruction-override",
                    severity="high",
                    description=f"Instruction override attempt: {kw}",
                    evidence=[{"keyword": kw, "source": ev.get("source", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_delimiter_escape(events: list, counters: dict) -> list[HijackDetection]:
    detections = []
    for ev in events:
        text = _get_text(ev)
        for delim in _DELIMITER_ESCAPES:
            if delim.lower() in text:
                detections.append(HijackDetection(
                    detection_id=_next_id(counters, "PH"),
                    agent_id=ev.get("agent_id", "unknown"),
                    hijack_type="delimiter-escape",
                    severity="high",
                    description=f"Delimiter escape attempt: {delim}",
                    evidence=[{"delimiter": delim, "source": ev.get("source", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_role_manipulation(events: list, counters: dict) -> list[HijackDetection]:
    detections = []
    for ev in events:
        text = _get_text(ev)
        for pat in _ROLE_MANIPULATIONS:
            m = pat.search(text)
            if m:
                detections.append(HijackDetection(
                    detection_id=_next_id(counters, "PH"),
                    agent_id=ev.get("agent_id", "unknown"),
                    hijack_type="role-manipulation",
                    severity="critical",
                    description=f"Role manipulation attempt: {m.group()[:60]}",
                    evidence=[{"pattern": m.group(), "source": ev.get("source", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_context_poison(events: list, counters: dict) -> list[HijackDetection]:
    detections = []
    agent_msgs: dict[str, list] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_msgs[agent].append(ev)
    for agent, msgs in agent_msgs.items():
        if len(msgs) < 3:
            continue
        injection_count = 0
        for ev in msgs:
            text = _get_text(ev)
            if any(p.search(text) for p in _INJECTION_PATTERNS) or \
               any(kw in text for kw in _OVERRIDE_KEYWORDS):
                injection_count += 1
        if injection_count >= 3:
            detections.append(HijackDetection(
                detection_id=_next_id(counters, "PH"),
                agent_id=agent,
                hijack_type="context-poisoning",
                severity="critical",
                description=f"Sustained context poisoning: {injection_count} injection attempts from agent",
                evidence=[{"injection_count": injection_count, "total_messages": len(msgs)}],
                timestamp=msgs[-1].get("timestamp", ""),
            ))
    return detections


def analyze_prompt_hijack(events: list) -> HijackReport:
    if not events:
        return HijackReport()

    counters: dict = {}
    detections: list[HijackDetection] = []
    detections.extend(_detect_injection(events, counters))
    detections.extend(_detect_override(events, counters))
    detections.extend(_detect_delimiter_escape(events, counters))
    detections.extend(_detect_role_manipulation(events, counters))
    detections.extend(_detect_context_poison(events, counters))

    agent_map: dict[str, AgentHijackScore] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentHijackScore(agent_id=d.agent_id)
        s = agent_map[d.agent_id]
        s.total_detections += 1
        s.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.hijack_type not in s.hijack_types:
            s.hijack_types.append(d.hijack_type)

    agents = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    hijack_types = list(set(d.hijack_type for d in detections))

    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return HijackReport(
        detections=detections,
        agent_scores=agents,
        summary=HijackSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            hijack_types=hijack_types,
        ),
    )


def format_text(report: HijackReport) -> str:
    lines = [
        "Prompt Hijack Detection Report",
        "=" * 62, "",
        f"  Total detections:    {report.summary.total_detections}",
        f"  Agents involved:     {report.summary.agents_involved}",
        f"  Highest severity:    {report.summary.highest_severity}",
        "",
    ]
    if report.detections:
        lines.append("  Detections:")
        lines.append("  " + "-" * 60)
        for d in report.detections:
            lines.append(f"    [{d.detection_id}] {d.hijack_type} ({d.severity})")
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


def format_json(report: HijackReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
