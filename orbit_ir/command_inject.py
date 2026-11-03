"""Command injection detection for AI agent interactions.

Detects shell metacharacter injection, pipe chains, encoded commands,
backtick execution, and subshell attempts in agent tool calls.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List


@dataclass
class InjectDetection:
    detection_id: str
    agent_id: str
    inject_type: str  # shell-meta, pipe-chain, encoded-cmd, backtick-exec, subshell
    severity: str
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentInjectScore:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    inject_types: list = field(default_factory=list)


@dataclass
class InjectSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    inject_types: list = field(default_factory=list)


@dataclass
class InjectReport:
    detections: List[InjectDetection] = field(default_factory=list)
    agent_scores: List[AgentInjectScore] = field(default_factory=list)
    summary: InjectSummary = field(default_factory=InjectSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_SHELL_META_PATTERNS = [
    (re.compile(r";\s*(rm|cat|wget|curl|nc|bash|sh|python|perl|ruby)\b"), "command chaining with semicolon"),
    (re.compile(r"&&\s*(rm|cat|wget|curl|nc|bash|sh)\b"), "conditional chain with dangerous command"),
    (re.compile(r"\|\|\s*(rm|wget|curl|nc|bash|sh)\b"), "or-chain with dangerous command"),
]

_PIPE_CHAIN_PATTERNS = [
    (re.compile(r"\|\s*(sh|bash|python|perl|ruby|node)\b"), "pipe to interpreter"),
    (re.compile(r"\|\s*base64\s+-d"), "pipe to base64 decode"),
    (re.compile(r"curl\s+.*\|\s*sh"), "curl pipe to shell"),
    (re.compile(r"wget\s+.*-O\s*-\s*\|\s*sh"), "wget pipe to shell"),
]

_ENCODED_CMD_PATTERNS = [
    (re.compile(r"base64\s+-d|base64\s+--decode"), "base64 decode execution"),
    (re.compile(r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64"), "encoded payload decode"),
    (re.compile(r"\\x[0-9a-fA-F]{2}"), "hex-encoded characters"),
    (re.compile(r"\$\(printf\s+'\\"), "printf escape sequence"),
]

_BACKTICK_PATTERN = re.compile(r"`[^`]{3,}`")
_SUBSHELL_PATTERN = re.compile(r"\$\([^)]{3,}\)")
_DANGEROUS_REDIRECT = re.compile(r">\s*/etc/|>\s*/proc/|>\s*/dev/|>\s*~/.ssh/")


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _get_command(ev: dict) -> str:
    for key in ("command", "cmd", "input", "args", "content"):
        val = ev.get(key, "")
        if isinstance(val, str) and val:
            return val
        if isinstance(val, list):
            return " ".join(str(v) for v in val)
    return ""


def _detect_shell_meta(events: list, counters: dict) -> list[InjectDetection]:
    detections = []
    for ev in events:
        cmd = _get_command(ev)
        if not cmd:
            continue
        for pattern, desc in _SHELL_META_PATTERNS:
            if pattern.search(cmd):
                detections.append(InjectDetection(
                    detection_id=_next_id(counters, "CI"),
                    agent_id=ev.get("agent_id", "unknown"),
                    inject_type="shell-meta",
                    severity="critical",
                    description=f"Shell metacharacter injection: {desc}",
                    evidence=[{"pattern": desc, "command_snippet": cmd[:200]}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_pipe_chain(events: list, counters: dict) -> list[InjectDetection]:
    detections = []
    for ev in events:
        cmd = _get_command(ev)
        if not cmd:
            continue
        for pattern, desc in _PIPE_CHAIN_PATTERNS:
            if pattern.search(cmd):
                detections.append(InjectDetection(
                    detection_id=_next_id(counters, "CI"),
                    agent_id=ev.get("agent_id", "unknown"),
                    inject_type="pipe-chain",
                    severity="critical",
                    description=f"Dangerous pipe chain: {desc}",
                    evidence=[{"pattern": desc, "command_snippet": cmd[:200]}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_encoded_cmd(events: list, counters: dict) -> list[InjectDetection]:
    detections = []
    for ev in events:
        cmd = _get_command(ev)
        if not cmd:
            continue
        for pattern, desc in _ENCODED_CMD_PATTERNS:
            if pattern.search(cmd):
                detections.append(InjectDetection(
                    detection_id=_next_id(counters, "CI"),
                    agent_id=ev.get("agent_id", "unknown"),
                    inject_type="encoded-cmd",
                    severity="high",
                    description=f"Encoded command execution: {desc}",
                    evidence=[{"pattern": desc}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_backtick_exec(events: list, counters: dict) -> list[InjectDetection]:
    detections = []
    for ev in events:
        cmd = _get_command(ev)
        if not cmd:
            continue
        if _BACKTICK_PATTERN.search(cmd):
            detections.append(InjectDetection(
                detection_id=_next_id(counters, "CI"),
                agent_id=ev.get("agent_id", "unknown"),
                inject_type="backtick-exec",
                severity="high",
                description="Backtick command substitution detected",
                evidence=[{"command_snippet": cmd[:200]}],
                timestamp=ev.get("timestamp", ""),
            ))
    return detections


def _detect_subshell(events: list, counters: dict) -> list[InjectDetection]:
    detections = []
    for ev in events:
        cmd = _get_command(ev)
        if not cmd:
            continue
        if _SUBSHELL_PATTERN.search(cmd):
            detections.append(InjectDetection(
                detection_id=_next_id(counters, "CI"),
                agent_id=ev.get("agent_id", "unknown"),
                inject_type="subshell",
                severity="high",
                description="Subshell command execution detected",
                evidence=[{"command_snippet": cmd[:200]}],
                timestamp=ev.get("timestamp", ""),
            ))
        if _DANGEROUS_REDIRECT.search(cmd):
            detections.append(InjectDetection(
                detection_id=_next_id(counters, "CI"),
                agent_id=ev.get("agent_id", "unknown"),
                inject_type="shell-meta",
                severity="critical",
                description="Dangerous redirect to sensitive path",
                evidence=[{"command_snippet": cmd[:200]}],
                timestamp=ev.get("timestamp", ""),
            ))
    return detections


def analyze_command_inject(events: list) -> InjectReport:
    if not events:
        return InjectReport()

    counters: dict = {}
    detections: list[InjectDetection] = []
    detections.extend(_detect_shell_meta(events, counters))
    detections.extend(_detect_pipe_chain(events, counters))
    detections.extend(_detect_encoded_cmd(events, counters))
    detections.extend(_detect_backtick_exec(events, counters))
    detections.extend(_detect_subshell(events, counters))

    agent_map: dict[str, AgentInjectScore] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentInjectScore(agent_id=d.agent_id)
        s = agent_map[d.agent_id]
        s.total_detections += 1
        s.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.inject_type not in s.inject_types:
            s.inject_types.append(d.inject_type)

    agents = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    inject_types = list(set(d.inject_type for d in detections))
    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return InjectReport(
        detections=detections,
        agent_scores=agents,
        summary=InjectSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            inject_types=inject_types,
        ),
    )


def format_text(report: InjectReport) -> str:
    lines = [
        "Command Injection Detection Report",
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
            lines.append(f"    [{d.detection_id}] {d.inject_type} ({d.severity})")
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


def format_json(report: InjectReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
