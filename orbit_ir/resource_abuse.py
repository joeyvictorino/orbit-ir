"""Resource abuse pattern detection for agent evidence.

Detects agents abusing computational, storage, API, or bandwidth
resources—excessive API call rates, storage quota abuse, compute
hijacking (crypto-mining patterns), and bandwidth saturation.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ABUSE_TYPES = {
    "excessive-api-calls",
    "storage-quota-abuse",
    "compute-hijacking",
    "bandwidth-abuse",
    "rate-limit-violation",
}

COMPUTE_KEYWORDS = {
    "mine", "miner", "mining", "hash", "hashrate", "crypto",
    "benchmark", "stress", "brute", "crack", "gpu", "compute",
}

STORAGE_KEYWORDS = {
    "write", "upload", "store", "create_file", "append",
    "copy", "replicate", "dump", "backup",
}


@dataclass
class AbusePattern:
    """A single detected resource abuse pattern."""
    pattern_id: str
    agent_id: str
    abuse_type: str
    timestamp_start: str
    timestamp_end: str
    event_count: int
    severity: str
    confidence: float
    detail: str
    resource: str
    estimated_impact: str


@dataclass
class AgentAbuseSummary:
    """Abuse summary for a single agent."""
    agent_id: str
    patterns: list[AbusePattern] = field(default_factory=list)
    total_events: int = 0
    peak_rate: float = 0.0
    abuse_types: list[str] = field(default_factory=list)


@dataclass
class AbuseSummary:
    total_patterns: int
    critical_patterns: int
    high_patterns: int
    agents_abusing: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class AbuseReport:
    patterns: list[AbusePattern]
    agent_summaries: list[AgentAbuseSummary]
    summary: AbuseSummary
    agents_involved: list[str]


def _parse_timestamp(ts: str) -> float:
    """Parse ISO timestamp to epoch-like float for ordering."""
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ts)
    if not m:
        return 0.0
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    return y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60 + s


def _detect_excessive_api(
    agent: str, events: list[dict[str, Any]], threshold: int = 10,
    window_seconds: float = 60.0,
) -> list[AbusePattern]:
    """Detect excessive API call rates within time windows."""
    patterns: list[AbusePattern] = []
    if len(events) < threshold:
        return patterns

    timestamps = [(_parse_timestamp(e.get("timestamp", "")), e) for e in events]
    timestamps.sort(key=lambda x: x[0])

    i = 0
    while i < len(timestamps):
        window_start = timestamps[i][0]
        window_end = window_start + window_seconds
        window_events = []
        j = i
        while j < len(timestamps) and timestamps[j][0] <= window_end:
            window_events.append(timestamps[j])
            j += 1

        if len(window_events) >= threshold:
            rate = len(window_events) / window_seconds * 60
            severity = "critical" if len(window_events) >= threshold * 3 else (
                "high" if len(window_events) >= threshold * 2 else "medium"
            )
            patterns.append(AbusePattern(
                pattern_id="",
                agent_id=agent,
                abuse_type="excessive-api-calls",
                timestamp_start=window_events[0][1].get("timestamp", ""),
                timestamp_end=window_events[-1][1].get("timestamp", ""),
                event_count=len(window_events),
                severity=severity,
                confidence=min(0.95, 0.5 + len(window_events) / (threshold * 4)),
                detail=f"{len(window_events)} API calls in {window_seconds}s window ({rate:.0f}/min)",
                resource="api",
                estimated_impact=f"~{rate:.0f} calls/min sustained",
            ))
            i = j
        else:
            i += 1

    return patterns


def _detect_storage_abuse(
    agent: str, events: list[dict[str, Any]], threshold_bytes: int = 1_000_000,
) -> list[AbusePattern]:
    """Detect storage quota abuse patterns."""
    patterns: list[AbusePattern] = []
    storage_events = [
        e for e in events
        if any(kw in e.get("tool", e.get("claimed_tool", "")).lower() for kw in STORAGE_KEYWORDS)
        or any(kw in e.get("effect", "").lower() for kw in STORAGE_KEYWORDS)
    ]
    if not storage_events:
        return patterns

    total_bytes = sum(e.get("bytes", e.get("size", 0)) for e in storage_events)
    if total_bytes >= threshold_bytes or len(storage_events) >= 20:
        ts_sorted = sorted(storage_events, key=lambda e: e.get("timestamp", ""))
        severity = "critical" if total_bytes >= threshold_bytes * 5 else (
            "high" if total_bytes >= threshold_bytes * 2 else "medium"
        )
        patterns.append(AbusePattern(
            pattern_id="",
            agent_id=agent,
            abuse_type="storage-quota-abuse",
            timestamp_start=ts_sorted[0].get("timestamp", ""),
            timestamp_end=ts_sorted[-1].get("timestamp", ""),
            event_count=len(storage_events),
            severity=severity,
            confidence=min(0.9, 0.4 + total_bytes / (threshold_bytes * 10)),
            detail=f"{len(storage_events)} storage operations, ~{total_bytes} bytes written",
            resource="storage",
            estimated_impact=f"~{total_bytes:,} bytes consumed",
        ))

    return patterns


def _detect_compute_hijacking(
    agent: str, events: list[dict[str, Any]],
) -> list[AbusePattern]:
    """Detect compute hijacking (crypto mining, brute force, etc.)."""
    patterns: list[AbusePattern] = []
    suspicious = [
        e for e in events
        if any(
            kw in (e.get("tool", "") + e.get("claimed_tool", "") + e.get("resource", "") + e.get("effect", "")).lower()
            for kw in COMPUTE_KEYWORDS
        )
    ]
    if not suspicious:
        return patterns

    ts_sorted = sorted(suspicious, key=lambda e: e.get("timestamp", ""))
    keywords_found = set()
    for e in suspicious:
        combined = (e.get("tool", "") + e.get("claimed_tool", "") + e.get("resource", "") + e.get("effect", "")).lower()
        for kw in COMPUTE_KEYWORDS:
            if kw in combined:
                keywords_found.add(kw)

    severity = "critical" if len(keywords_found) >= 3 else (
        "high" if len(keywords_found) >= 2 else "medium"
    )
    patterns.append(AbusePattern(
        pattern_id="",
        agent_id=agent,
        abuse_type="compute-hijacking",
        timestamp_start=ts_sorted[0].get("timestamp", ""),
        timestamp_end=ts_sorted[-1].get("timestamp", ""),
        event_count=len(suspicious),
        severity=severity,
        confidence=min(0.9, 0.3 + len(keywords_found) * 0.15),
        detail=f"{len(suspicious)} compute-related events, keywords: {', '.join(sorted(keywords_found))}",
        resource="compute",
        estimated_impact=f"{len(suspicious)} suspicious compute operations",
    ))

    return patterns


def _detect_bandwidth_abuse(
    agent: str, events: list[dict[str, Any]], threshold_bytes: int = 5_000_000,
) -> list[AbusePattern]:
    """Detect bandwidth abuse patterns."""
    patterns: list[AbusePattern] = []
    network_events = [
        e for e in events
        if any(kw in (e.get("tool", "") + e.get("effect", "")).lower()
               for kw in ("send", "transfer", "upload", "download", "exfil", "network", "http"))
    ]
    if not network_events:
        return patterns

    total_bytes = sum(e.get("bytes", e.get("size", 0)) for e in network_events)
    if total_bytes >= threshold_bytes or len(network_events) >= 50:
        ts_sorted = sorted(network_events, key=lambda e: e.get("timestamp", ""))
        severity = "critical" if total_bytes >= threshold_bytes * 5 else (
            "high" if total_bytes >= threshold_bytes * 2 else "medium"
        )
        patterns.append(AbusePattern(
            pattern_id="",
            agent_id=agent,
            abuse_type="bandwidth-abuse",
            timestamp_start=ts_sorted[0].get("timestamp", ""),
            timestamp_end=ts_sorted[-1].get("timestamp", ""),
            event_count=len(network_events),
            severity=severity,
            confidence=min(0.85, 0.3 + total_bytes / (threshold_bytes * 10)),
            detail=f"{len(network_events)} network operations, ~{total_bytes:,} bytes transferred",
            resource="network",
            estimated_impact=f"~{total_bytes:,} bytes bandwidth consumed",
        ))

    return patterns


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
    api_threshold: int = 10,
    window_seconds: float = 60.0,
    storage_threshold: int = 1_000_000,
    bandwidth_threshold: int = 5_000_000,
) -> AbuseReport:
    """Detect resource abuse patterns from event evidence."""
    if control_events is None:
        control_events = []

    all_events = control_events + events
    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in all_events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    all_patterns: list[AbusePattern] = []
    agent_summaries: list[AgentAbuseSummary] = []
    pattern_counter = 0

    for agent, agent_events in sorted(by_agent.items()):
        agent_patterns: list[AbusePattern] = []

        agent_patterns.extend(_detect_excessive_api(agent, agent_events, api_threshold, window_seconds))
        agent_patterns.extend(_detect_storage_abuse(agent, agent_events, storage_threshold))
        agent_patterns.extend(_detect_compute_hijacking(agent, agent_events))
        agent_patterns.extend(_detect_bandwidth_abuse(agent, agent_events, bandwidth_threshold))

        for p in agent_patterns:
            pattern_counter += 1
            p.pattern_id = f"RA-{pattern_counter:03d}"

        if agent_patterns:
            timestamps = [_parse_timestamp(e.get("timestamp", "")) for e in agent_events]
            if len(timestamps) >= 2:
                duration = max(timestamps) - min(timestamps)
                peak_rate = len(agent_events) / max(duration / 60, 1)
            else:
                peak_rate = float(len(agent_events))

            agent_summaries.append(AgentAbuseSummary(
                agent_id=agent,
                patterns=agent_patterns,
                total_events=len(agent_events),
                peak_rate=peak_rate,
                abuse_types=sorted(set(p.abuse_type for p in agent_patterns)),
            ))
            all_patterns.extend(agent_patterns)

    all_patterns.sort(key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p.severity, 4))

    sev_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for p in all_patterns:
        sev_counts[p.severity] += 1
        type_counts[p.abuse_type] += 1

    all_agents = sorted({p.agent_id for p in all_patterns})

    return AbuseReport(
        patterns=all_patterns,
        agent_summaries=agent_summaries,
        summary=AbuseSummary(
            total_patterns=len(all_patterns),
            critical_patterns=sev_counts.get("critical", 0),
            high_patterns=sev_counts.get("high", 0),
            agents_abusing=len(all_agents),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
        ),
        agents_involved=all_agents,
    )


def format_text(report: AbuseReport) -> str:
    lines: list[str] = []
    lines.append("Resource Abuse Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:         {s.total_patterns}")
    lines.append(f"  Critical patterns:      {s.critical_patterns}")
    lines.append(f"  High severity:          {s.high_patterns}")
    lines.append(f"  Agents abusing:         {s.agents_abusing}")
    lines.append("")

    if s.by_type:
        lines.append("  By type:")
        for t, cnt in sorted(s.by_type.items()):
            lines.append(f"    {t}: {cnt}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity.upper()}] {p.pattern_id}: {p.agent_id}")
        lines.append(f"    Type: {p.abuse_type}")
        lines.append(f"    {p.detail}")
        lines.append(f"    Timespan: {p.timestamp_start} to {p.timestamp_end}")
        lines.append(f"    Events: {p.event_count}, Confidence: {p.confidence:.0%}")
        lines.append(f"    Impact: {p.estimated_impact}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AbuseReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "agent_summaries": [
            {
                **{k: v for k, v in asdict(a).items() if k != "patterns"},
                "patterns": [asdict(p) for p in a.patterns],
            }
            for a in report.agent_summaries
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def _load_events(evidence_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    control: list[dict[str, Any]] = []
    transcript_path = evidence_dir / "transcripts.jsonl"
    control_path = evidence_dir / "control_plane.jsonl"
    if transcript_path.exists():
        for line in transcript_path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    if control_path.exists():
        for line in control_path.read_text().splitlines():
            line = line.strip()
            if line:
                control.append(json.loads(line))
    return events, control
