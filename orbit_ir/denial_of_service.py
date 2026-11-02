"""Denial of service pattern detection in agent evidence.

Identifies attempts to overwhelm AI systems through resource exhaustion,
prompt flooding, infinite loop induction, memory exhaustion attacks,
and rate limit abuse patterns.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


PROMPT_FLOOD_KEYWORDS = {
    "repeat", "loop", "infinite", "recursion", "recursive",
    "while true", "for ever", "keep going", "don't stop",
    "never stop", "continuous", "non-stop", "flood",
    "spam", "ddos", "overwhelm", "overload",
}

RESOURCE_EXHAUST_KEYWORDS = {
    "maximum length", "max tokens", "fill context", "context window",
    "token limit", "memory limit", "exhaust", "consume all",
    "out of memory", "oom", "stack overflow", "heap",
    "disk full", "storage limit", "quota exceeded",
}

RATE_ABUSE_KEYWORDS = {
    "rate limit", "throttle", "bypass rate", "circumvent limit",
    "api abuse", "rapid fire", "concurrent requests",
    "parallel requests", "batch flood", "burst",
    "retry storm", "exponential", "backoff bypass",
}

LOOP_INDUCTION_KEYWORDS = {
    "infinite loop", "circular reference", "self-reference",
    "call yourself", "invoke yourself", "recursive call",
    "mutual recursion", "ping pong", "deadlock",
    "livelock", "busy wait", "spin lock",
}

AMPLIFICATION_KEYWORDS = {
    "amplification", "fan out", "fork bomb", "cascade",
    "chain reaction", "snowball", "exponential growth",
    "spawn", "multiply", "replicate instances",
    "nested calls", "deep recursion", "expansion",
}

DOS_TYPES = {
    "prompt-flood": "Overwhelming system with excessive prompt submissions",
    "resource-exhaustion": "Consuming system resources (memory, tokens, storage)",
    "rate-abuse": "Abusing or bypassing API rate limits",
    "loop-induction": "Inducing infinite loops or recursive patterns",
    "amplification": "Triggering amplification attacks through cascading operations",
}

_KEYWORD_SETS = {
    "prompt-flood": PROMPT_FLOOD_KEYWORDS,
    "resource-exhaustion": RESOURCE_EXHAUST_KEYWORDS,
    "rate-abuse": RATE_ABUSE_KEYWORDS,
    "loop-induction": LOOP_INDUCTION_KEYWORDS,
    "amplification": AMPLIFICATION_KEYWORDS,
}


@dataclass
class Pattern:
    dos_type: str
    agent: str
    timestamp: str
    description: str
    evidence_field: str
    matched_keywords: list[str]
    severity: str = "high"


@dataclass
class DoSCampaign:
    agent: str
    types_involved: list[str]
    pattern_count: int
    first_seen: str
    last_seen: str
    severity: str = "critical"


@dataclass
class Summary:
    total_events: int = 0
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: list[str] = field(default_factory=list)
    campaigns: int = 0


@dataclass
class Report:
    patterns: list[Pattern] = field(default_factory=list)
    campaigns: list[DoSCampaign] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(kw for kw in keyword_set if kw in lower)


def _detect_rapid_fire(events: list[dict[str, Any]]) -> list[Pattern]:
    """Detect abnormally rapid event submission from a single agent."""
    patterns: list[Pattern] = []
    agent_events: dict[str, list[dict]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent", ev.get("agent_id", "unknown"))
        agent_events[agent].append(ev)

    for agent, evts in agent_events.items():
        timestamps = []
        for ev in evts:
            ts = ev.get("timestamp", "")
            if ts:
                timestamps.append(ts)

        if len(timestamps) >= 2:
            timestamps.sort()
            rapid_bursts = 0
            for i in range(1, min(len(timestamps), 100)):
                if timestamps[i] == timestamps[i - 1]:
                    rapid_bursts += 1

            if rapid_bursts >= 10:
                patterns.append(Pattern(
                    dos_type="prompt-flood",
                    agent=agent,
                    timestamp=timestamps[0],
                    description=f"Agent has {rapid_bursts} events with identical timestamps — potential flood",
                    evidence_field="timestamp",
                    matched_keywords=["rapid fire", "same timestamp"],
                    severity="critical" if rapid_bursts >= 20 else "high",
                ))

    return patterns


def _detect_large_payloads(events: list[dict[str, Any]]) -> list[Pattern]:
    """Detect abnormally large payloads that could exhaust resources."""
    patterns: list[Pattern] = []

    for ev in events:
        agent = ev.get("agent", ev.get("agent_id", "unknown"))
        ts = ev.get("timestamp", "")

        for field_name in ("content", "args", "message"):
            text = str(ev.get(field_name, ""))
            if len(text) > 10000:
                patterns.append(Pattern(
                    dos_type="resource-exhaustion",
                    agent=agent,
                    timestamp=ts,
                    description=f"Large payload ({len(text)} chars) in {field_name} — potential resource exhaustion",
                    evidence_field=field_name,
                    matched_keywords=["large payload"],
                    severity="high" if len(text) > 50000 else "medium",
                ))

    return patterns


def _detect_keyword_patterns(events: list[dict[str, Any]]) -> list[Pattern]:
    """Detect DoS patterns via keyword matching."""
    patterns: list[Pattern] = []

    for ev in events:
        agent = ev.get("agent", ev.get("agent_id", "unknown"))
        ts = ev.get("timestamp", "")

        for field_name in ("content", "tool", "args", "result", "message"):
            text = str(ev.get(field_name, ""))
            if not text:
                continue

            for dtype, kw_set in _KEYWORD_SETS.items():
                matched = _match_keywords(text, kw_set)
                if len(matched) >= 2:
                    severity = _classify_severity(dtype, len(matched))
                    patterns.append(Pattern(
                        dos_type=dtype,
                        agent=agent,
                        timestamp=ts,
                        description=f"{DOS_TYPES[dtype]} ({len(matched)} indicators in {field_name})",
                        evidence_field=field_name,
                        matched_keywords=matched,
                        severity=severity,
                    ))

    return patterns


def _classify_severity(dos_type: str, match_count: int) -> str:
    if dos_type in ("amplification", "loop-induction"):
        return "critical" if match_count >= 3 else "high"
    if dos_type == "prompt-flood":
        return "high" if match_count >= 2 else "medium"
    return "high" if match_count >= 3 else "medium"


def _build_campaigns(patterns: list[Pattern]) -> list[DoSCampaign]:
    """Group patterns by agent to find multi-vector DoS campaigns."""
    agent_patterns: dict[str, list[Pattern]] = defaultdict(list)
    for p in patterns:
        agent_patterns[p.agent].append(p)

    campaigns: list[DoSCampaign] = []
    for agent, pats in agent_patterns.items():
        types = sorted(set(p.dos_type for p in pats))
        if len(types) >= 2:
            timestamps = [p.timestamp for p in pats if p.timestamp]
            campaigns.append(DoSCampaign(
                agent=agent,
                types_involved=types,
                pattern_count=len(pats),
                first_seen=min(timestamps) if timestamps else "",
                last_seen=max(timestamps) if timestamps else "",
                severity="critical",
            ))

    return sorted(campaigns, key=lambda c: c.pattern_count, reverse=True)


def _load_events(evidence_dir: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    ed = Path(evidence_dir)
    for name in ("transcripts.jsonl", "control_plane.jsonl"):
        fp = ed / name
        if fp.exists():
            for line in fp.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return events


def analyze(events: list[dict[str, Any]]) -> Report:
    kw_patterns = _detect_keyword_patterns(events)
    rapid_patterns = _detect_rapid_fire(events)
    payload_patterns = _detect_large_payloads(events)
    all_patterns = kw_patterns + rapid_patterns + payload_patterns

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_patterns.sort(key=lambda p: (severity_order.get(p.severity, 9), p.timestamp))

    campaigns = _build_campaigns(all_patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents = set()
    for p in all_patterns:
        by_type[p.dos_type] += 1
        agents.add(p.agent)

    summary = Summary(
        total_events=len(events),
        total_patterns=len(all_patterns),
        by_type=dict(by_type),
        agents_involved=sorted(agents),
        campaigns=len(campaigns),
    )

    return Report(patterns=all_patterns, campaigns=campaigns, summary=summary)


def format_text(report: Report) -> str:
    lines = [
        "Denial of Service Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:   {report.summary.total_events}",
        f"  DoS patterns found:      {report.summary.total_patterns}",
        f"  DoS campaigns:           {report.summary.campaigns}",
        f"  Agents involved:         {len(report.summary.agents_involved)}",
        "",
    ]

    if report.summary.by_type:
        lines.append("  Patterns by type:")
        for t, c in sorted(report.summary.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity.upper()}] {p.dos_type}")
        lines.append(f"    Agent: {p.agent}")
        if p.timestamp:
            lines.append(f"    Time:  {p.timestamp}")
        lines.append(f"    Detail: {p.description}")
        lines.append(f"    Keywords: {', '.join(p.matched_keywords)}")
        lines.append("")

    if report.campaigns:
        lines.append("  DoS Campaigns:")
        for c in report.campaigns:
            lines.append(f"    Agent: {c.agent} ({c.pattern_count} patterns)")
            lines.append(f"    Vectors: {', '.join(c.types_involved)}")
            if c.first_seen:
                lines.append(f"    Window: {c.first_seen} -> {c.last_seen}")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: Report) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"
