"""Log pattern anomaly detection for agent evidence.

Detects anomalous patterns in agent log evidence including frequency
spikes, novel log entries, time gap anomalies, and repetitive patterns.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass
class LogAnomaly:
    anomaly_id: str
    anomaly_type: str
    agent_id: str
    timestamp: str
    severity: str
    confidence: float
    description: str
    evidence: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class LogAnomalyReport:
    anomalies: list[LogAnomaly]
    summary: LogAnomalySummary
    agents_analyzed: list[str]


@dataclass
class LogAnomalySummary:
    total_anomalies: int
    critical_anomalies: int
    high_anomalies: int
    agents_with_anomalies: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _detect_frequency_spikes(
    events: list[dict[str, Any]],
    window_seconds: int = 10,
    spike_factor: float = 3.0,
) -> list[LogAnomaly]:
    anomalies: list[LogAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        ts = _parse_ts(ev.get("timestamp", ""))
        if ts and agent:
            by_agent[agent].append((ts, ev))

    anomaly_counter = 0
    for agent, agent_events in sorted(by_agent.items()):
        agent_events.sort(key=lambda x: x[0])
        if len(agent_events) < 3:
            continue

        total_span = (agent_events[-1][0] - agent_events[0][0]).total_seconds()
        if total_span <= 0:
            continue

        avg_rate = len(agent_events) / (total_span / window_seconds)

        i = 0
        while i < len(agent_events):
            window_start = agent_events[i][0]
            window_end = window_start + timedelta(seconds=window_seconds)
            window_events = []
            j = i
            while j < len(agent_events) and agent_events[j][0] <= window_end:
                window_events.append(agent_events[j])
                j += 1

            if len(window_events) > avg_rate * spike_factor and len(window_events) >= 3:
                anomaly_counter += 1
                ratio = len(window_events) / max(avg_rate, 0.1)
                severity = "critical" if ratio > 10 else "high" if ratio > 5 else "medium"
                confidence = min(0.95, 0.5 + (ratio - spike_factor) * 0.1)
                anomalies.append(LogAnomaly(
                    anomaly_id=f"LA-{anomaly_counter:03d}",
                    anomaly_type="frequency-spike",
                    agent_id=agent,
                    timestamp=window_events[0][1].get("timestamp", ""),
                    severity=severity,
                    confidence=round(confidence, 2),
                    description=f"Agent '{agent}' produced {len(window_events)} events in {window_seconds}s window (avg {avg_rate:.1f})",
                    evidence=[e[1].get("timestamp", "") for e in window_events[:5]],
                    context={"window_count": len(window_events), "average_rate": round(avg_rate, 2), "ratio": round(ratio, 2)},
                ))
            i = max(j, i + 1)

    return anomalies


def _detect_novel_entries(
    events: list[dict[str, Any]],
    baseline_fraction: float = 0.5,
) -> list[LogAnomaly]:
    anomalies: list[LogAnomaly] = []
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    anomaly_counter = 0
    for agent, agent_events in sorted(by_agent.items()):
        if len(agent_events) < 4:
            continue
        split = int(len(agent_events) * baseline_fraction)
        baseline = agent_events[:split]
        remaining = agent_events[split:]

        baseline_tools = {ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", ""))) for ev in baseline}
        baseline_tools.discard("")

        for ev in remaining:
            tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
            if tool and tool not in baseline_tools:
                anomaly_counter += 1
                anomalies.append(LogAnomaly(
                    anomaly_id=f"LA-{anomaly_counter:03d}",
                    anomaly_type="novel-entry",
                    agent_id=agent,
                    timestamp=ev.get("timestamp", ""),
                    severity="medium",
                    confidence=0.7,
                    description=f"Agent '{agent}' used novel tool '{tool}' not seen in baseline",
                    evidence=[ev.get("timestamp", "")],
                    context={"novel_tool": tool, "baseline_tools": sorted(baseline_tools)[:10]},
                ))

    return anomalies


def _detect_time_gaps(
    events: list[dict[str, Any]],
    gap_factor: float = 5.0,
) -> list[LogAnomaly]:
    anomalies: list[LogAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        ts = _parse_ts(ev.get("timestamp", ""))
        if ts and agent:
            by_agent[agent].append((ts, ev))

    anomaly_counter = 0
    for agent, agent_events in sorted(by_agent.items()):
        agent_events.sort(key=lambda x: x[0])
        if len(agent_events) < 3:
            continue

        gaps = []
        for i in range(1, len(agent_events)):
            gap = (agent_events[i][0] - agent_events[i - 1][0]).total_seconds()
            gaps.append(gap)

        if not gaps:
            continue

        avg_gap = sum(gaps) / len(gaps)
        if avg_gap <= 0:
            continue

        for i, gap in enumerate(gaps):
            if gap > avg_gap * gap_factor and gap > 1:
                anomaly_counter += 1
                ratio = gap / avg_gap
                severity = "high" if ratio > 20 else "medium" if ratio > 10 else "low"
                anomalies.append(LogAnomaly(
                    anomaly_id=f"LA-{anomaly_counter:03d}",
                    anomaly_type="time-gap",
                    agent_id=agent,
                    timestamp=agent_events[i + 1][1].get("timestamp", ""),
                    severity=severity,
                    confidence=round(min(0.9, 0.4 + ratio * 0.02), 2),
                    description=f"Agent '{agent}' had {gap:.0f}s gap (avg {avg_gap:.1f}s, {ratio:.1f}x)",
                    evidence=[
                        agent_events[i][1].get("timestamp", ""),
                        agent_events[i + 1][1].get("timestamp", ""),
                    ],
                    context={"gap_seconds": round(gap, 1), "avg_gap": round(avg_gap, 1), "ratio": round(ratio, 1)},
                ))

    return anomalies


def _detect_repetitive_patterns(
    events: list[dict[str, Any]],
    min_repeat: int = 3,
) -> list[LogAnomaly]:
    anomalies: list[LogAnomaly] = []
    by_agent: dict[str, list[dict]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    anomaly_counter = 0
    for agent, agent_events in sorted(by_agent.items()):
        if len(agent_events) < min_repeat:
            continue

        actions = []
        for ev in agent_events:
            tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
            resource = ev.get("resource", "")
            actions.append(f"{tool}:{resource}")

        i = 0
        while i < len(actions):
            count = 1
            while i + count < len(actions) and actions[i + count] == actions[i]:
                count += 1
            if count >= min_repeat:
                anomaly_counter += 1
                severity = "high" if count >= 10 else "medium" if count >= 5 else "low"
                anomalies.append(LogAnomaly(
                    anomaly_id=f"LA-{anomaly_counter:03d}",
                    anomaly_type="repetitive-pattern",
                    agent_id=agent,
                    timestamp=agent_events[i].get("timestamp", ""),
                    severity=severity,
                    confidence=round(min(0.95, 0.5 + count * 0.05), 2),
                    description=f"Agent '{agent}' repeated '{actions[i]}' {count} times consecutively",
                    evidence=[agent_events[j].get("timestamp", "") for j in range(i, min(i + 5, i + count))],
                    context={"action": actions[i], "repeat_count": count},
                ))
            i += count

    return anomalies


def analyze_log_anomalies(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> LogAnomalyReport:
    if control_events is None:
        control_events = []

    all_events = control_events + events

    anomalies: list[LogAnomaly] = []
    anomalies.extend(_detect_frequency_spikes(all_events))
    anomalies.extend(_detect_novel_entries(all_events))
    anomalies.extend(_detect_time_gaps(all_events))
    anomalies.extend(_detect_repetitive_patterns(all_events))

    anomalies.sort(key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.severity, 4))

    for i, a in enumerate(anomalies):
        a.anomaly_id = f"LA-{i + 1:03d}"

    all_agents = sorted({a.agent_id for a in anomalies})
    type_counts: dict[str, int] = Counter(a.anomaly_type for a in anomalies)
    sev_counts: dict[str, int] = Counter(a.severity for a in anomalies)

    return LogAnomalyReport(
        anomalies=anomalies,
        summary=LogAnomalySummary(
            total_anomalies=len(anomalies),
            critical_anomalies=sev_counts.get("critical", 0),
            high_anomalies=sev_counts.get("high", 0),
            agents_with_anomalies=len(all_agents),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
        ),
        agents_analyzed=all_agents,
    )


def _load_events(evidence_dir: Path) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    control: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    control_file = evidence_dir / "control_plane.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    if control_file.exists():
        for line in control_file.read_text().splitlines():
            if line.strip():
                control.append(json.loads(line))
    return events, control


def format_text(report: LogAnomalyReport) -> str:
    lines: list[str] = []
    lines.append("Log Anomaly Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total anomalies:        {s.total_anomalies}")
    lines.append(f"  Critical anomalies:     {s.critical_anomalies}")
    lines.append(f"  High severity:          {s.high_anomalies}")
    lines.append(f"  Agents with anomalies:  {s.agents_with_anomalies}")
    lines.append("")

    if s.by_type:
        lines.append("  By type:")
        for t, c in sorted(s.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    for a in report.anomalies:
        lines.append(f"  [{a.severity.upper()}] {a.anomaly_id}: {a.anomaly_type}")
        lines.append(f"    Agent: {a.agent_id}")
        lines.append(f"    {a.description}")
        lines.append(f"    Confidence: {a.confidence}")
        if a.evidence:
            lines.append(f"    Evidence: {', '.join(a.evidence[:3])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: LogAnomalyReport) -> str:
    data = {
        "anomalies": [asdict(a) for a in report.anomalies],
        "summary": asdict(report.summary),
        "agents_analyzed": report.agents_analyzed,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
