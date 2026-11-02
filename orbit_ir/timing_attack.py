"""Timing-based attack pattern detection in agent evidence.

Detects temporal anomalies: race conditions, TOCTOU gaps, coordinated
timing across agents, burst activity, dormant-then-active patterns,
and time window exploitation.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


BURST_THRESHOLD = 5
BURST_WINDOW_SECONDS = 10.0

TOCTOU_MAX_GAP_SECONDS = 30.0

COORDINATION_WINDOW_SECONDS = 2.0

DORMANT_THRESHOLD_SECONDS = 3600.0
DORMANT_BURST_ACTIONS = 3
DORMANT_BURST_WINDOW = 60.0

OFF_HOURS_START = 0
OFF_HOURS_END = 6


@dataclass
class TimingAnomaly:
    anomaly_type: str
    timestamp: str
    agent_id: str
    event_ids: list[str]
    description: str
    severity: str
    source_file: str
    line: int
    duration_seconds: float = 0.0
    related_agents: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)


@dataclass
class TimingAttackSummary:
    total_anomalies: int
    by_type: dict[str, int] = field(default_factory=dict)
    critical_anomalies: int = 0
    high_anomalies: int = 0
    agents_involved: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class TimingAttackReport:
    anomalies: list[TimingAnomaly]
    summary: TimingAttackSummary
    agents_involved: list[str]


def _parse_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


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


def _detect_bursts(
    sorted_events: list[tuple[datetime, dict[str, Any], str, int]],
) -> list[TimingAnomaly]:
    anomalies: list[TimingAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict[str, Any], str, int]]] = defaultdict(list)
    for item in sorted_events:
        agent = item[1].get("agent_id", "")
        by_agent[agent].append(item)

    for agent, agent_events in by_agent.items():
        if len(agent_events) < BURST_THRESHOLD:
            continue
        for i in range(len(agent_events)):
            window_events = []
            for j in range(i, len(agent_events)):
                diff = (agent_events[j][0] - agent_events[i][0]).total_seconds()
                if diff <= BURST_WINDOW_SECONDS:
                    window_events.append(agent_events[j])
                else:
                    break
            if len(window_events) >= BURST_THRESHOLD:
                eids = [
                    e[1].get("tool_call_id", e[1].get("event_id", ""))
                    for e in window_events
                ]
                resources = sorted({
                    e[1].get("resource", "") for e in window_events if e[1].get("resource")
                })
                duration = (window_events[-1][0] - window_events[0][0]).total_seconds()
                anomalies.append(TimingAnomaly(
                    anomaly_type="burst",
                    timestamp=agent_events[i][1].get("timestamp", ""),
                    agent_id=agent,
                    event_ids=eids,
                    description=f"Agent '{agent}' performed {len(window_events)} actions in {duration:.1f}s",
                    severity="high" if len(window_events) >= BURST_THRESHOLD * 2 else "medium",
                    source_file=window_events[0][2],
                    line=window_events[0][3],
                    duration_seconds=duration,
                    resources=resources,
                ))
                break

    return anomalies


def _detect_toctou(
    sorted_events: list[tuple[datetime, dict[str, Any], str, int]],
) -> list[TimingAnomaly]:
    anomalies: list[TimingAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict[str, Any], str, int]]] = defaultdict(list)
    for item in sorted_events:
        agent = item[1].get("agent_id", "")
        by_agent[agent].append(item)

    check_tools = {"check", "verify", "validate", "test", "read", "stat", "exists", "access"}
    use_tools = {"write", "modify", "create", "delete", "execute", "update", "set", "put"}

    for agent, agent_events in by_agent.items():
        for i in range(len(agent_events) - 1):
            ev_i = agent_events[i][1]
            tool_i = ev_i.get("actual_tool", ev_i.get("claimed_tool", ev_i.get("tool", ""))).lower()
            resource_i = ev_i.get("resource", "")

            is_check = any(c in tool_i for c in check_tools)
            if not is_check:
                continue

            for j in range(i + 1, len(agent_events)):
                ev_j = agent_events[j][1]
                tool_j = ev_j.get("actual_tool", ev_j.get("claimed_tool", ev_j.get("tool", ""))).lower()
                resource_j = ev_j.get("resource", "")

                if resource_i and resource_j and resource_i == resource_j:
                    is_use = any(u in tool_j for u in use_tools)
                    if is_use:
                        gap = (agent_events[j][0] - agent_events[i][0]).total_seconds()
                        if 0 < gap <= TOCTOU_MAX_GAP_SECONDS:
                            eid_i = ev_i.get("tool_call_id", ev_i.get("event_id", ""))
                            eid_j = ev_j.get("tool_call_id", ev_j.get("event_id", ""))
                            anomalies.append(TimingAnomaly(
                                anomaly_type="toctou",
                                timestamp=ev_i.get("timestamp", ""),
                                agent_id=agent,
                                event_ids=[eid_i, eid_j],
                                description=f"TOCTOU on '{resource_i}': check({tool_i}) then use({tool_j}) with {gap:.1f}s gap",
                                severity="high",
                                source_file=agent_events[i][2],
                                line=agent_events[i][3],
                                duration_seconds=gap,
                                resources=[resource_i],
                            ))
                            break

    return anomalies


def _detect_coordination(
    sorted_events: list[tuple[datetime, dict[str, Any], str, int]],
) -> list[TimingAnomaly]:
    anomalies: list[TimingAnomaly] = []
    seen_pairs: set[tuple[str, str]] = set()

    for i in range(len(sorted_events)):
        for j in range(i + 1, len(sorted_events)):
            dt_i, ev_i, src_i, ln_i = sorted_events[i]
            dt_j, ev_j, src_j, ln_j = sorted_events[j]
            gap = (dt_j - dt_i).total_seconds()
            if gap > COORDINATION_WINDOW_SECONDS:
                break

            agent_i = ev_i.get("agent_id", "")
            agent_j = ev_j.get("agent_id", "")
            if agent_i and agent_j and agent_i != agent_j:
                pair = tuple(sorted([agent_i, agent_j]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    eid_i = ev_i.get("tool_call_id", ev_i.get("event_id", ""))
                    eid_j = ev_j.get("tool_call_id", ev_j.get("event_id", ""))
                    resources = sorted({
                        r for r in [ev_i.get("resource", ""), ev_j.get("resource", "")]
                        if r
                    })
                    anomalies.append(TimingAnomaly(
                        anomaly_type="coordinated",
                        timestamp=ev_i.get("timestamp", ""),
                        agent_id=agent_i,
                        event_ids=[eid_i, eid_j],
                        description=f"Coordinated actions: '{agent_i}' and '{agent_j}' acted within {gap:.2f}s",
                        severity="medium",
                        source_file=src_i,
                        line=ln_i,
                        duration_seconds=gap,
                        related_agents=[agent_j],
                        resources=resources,
                    ))

    return anomalies


def _detect_dormant_burst(
    sorted_events: list[tuple[datetime, dict[str, Any], str, int]],
) -> list[TimingAnomaly]:
    anomalies: list[TimingAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict[str, Any], str, int]]] = defaultdict(list)
    for item in sorted_events:
        agent = item[1].get("agent_id", "")
        by_agent[agent].append(item)

    for agent, agent_events in by_agent.items():
        if len(agent_events) < 2:
            continue
        for i in range(1, len(agent_events)):
            gap = (agent_events[i][0] - agent_events[i - 1][0]).total_seconds()
            if gap >= DORMANT_THRESHOLD_SECONDS:
                burst_end = i
                for j in range(i + 1, len(agent_events)):
                    d = (agent_events[j][0] - agent_events[i][0]).total_seconds()
                    if d <= DORMANT_BURST_WINDOW:
                        burst_end = j
                    else:
                        break
                burst_count = burst_end - i + 1
                if burst_count >= DORMANT_BURST_ACTIONS:
                    eids = [
                        e[1].get("tool_call_id", e[1].get("event_id", ""))
                        for e in agent_events[i:burst_end + 1]
                    ]
                    anomalies.append(TimingAnomaly(
                        anomaly_type="dormant-burst",
                        timestamp=agent_events[i][1].get("timestamp", ""),
                        agent_id=agent,
                        event_ids=eids,
                        description=f"Agent '{agent}' dormant for {gap:.0f}s then {burst_count} actions in {DORMANT_BURST_WINDOW}s",
                        severity="high",
                        source_file=agent_events[i][2],
                        line=agent_events[i][3],
                        duration_seconds=gap,
                    ))
                    break

    return anomalies


def _detect_off_hours(
    sorted_events: list[tuple[datetime, dict[str, Any], str, int]],
) -> list[TimingAnomaly]:
    anomalies: list[TimingAnomaly] = []
    by_agent: dict[str, list[tuple[datetime, dict[str, Any], str, int]]] = defaultdict(list)
    for item in sorted_events:
        agent = item[1].get("agent_id", "")
        by_agent[agent].append(item)

    for agent, agent_events in by_agent.items():
        off_hour_events = [
            e for e in agent_events
            if OFF_HOURS_START <= e[0].hour < OFF_HOURS_END
        ]
        if len(off_hour_events) >= 2:
            eids = [
                e[1].get("tool_call_id", e[1].get("event_id", ""))
                for e in off_hour_events
            ]
            resources = sorted({
                e[1].get("resource", "") for e in off_hour_events if e[1].get("resource")
            })
            anomalies.append(TimingAnomaly(
                anomaly_type="off-hours",
                timestamp=off_hour_events[0][1].get("timestamp", ""),
                agent_id=agent,
                event_ids=eids,
                description=f"Agent '{agent}' performed {len(off_hour_events)} actions during off-hours (00:00-06:00 UTC)",
                severity="medium",
                source_file=off_hour_events[0][2],
                line=off_hour_events[0][3],
                resources=resources,
            ))

    return anomalies


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> TimingAttackReport:
    if control_events is None:
        control_events = []

    parsed: list[tuple[datetime, dict[str, Any], str, int]] = []
    for i, ev in enumerate(control_events):
        ts = ev.get("timestamp", "")
        dt = _parse_ts(ts)
        if dt:
            parsed.append((dt, ev, "control_plane.jsonl", i + 1))

    for i, ev in enumerate(events):
        ts = ev.get("timestamp", "")
        dt = _parse_ts(ts)
        if dt:
            parsed.append((dt, ev, "transcripts.jsonl", i + 1))

    parsed.sort(key=lambda x: x[0])

    all_anomalies: list[TimingAnomaly] = []
    all_anomalies.extend(_detect_bursts(parsed))
    all_anomalies.extend(_detect_toctou(parsed))
    all_anomalies.extend(_detect_coordination(parsed))
    all_anomalies.extend(_detect_dormant_burst(parsed))
    all_anomalies.extend(_detect_off_hours(parsed))

    all_anomalies.sort(key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.severity, 4))

    agents = sorted({a.agent_id for a in all_anomalies})
    by_type: dict[str, int] = defaultdict(int)
    by_sev: dict[str, int] = defaultdict(int)
    for a in all_anomalies:
        by_type[a.anomaly_type] += 1
        by_sev[a.severity] += 1

    return TimingAttackReport(
        anomalies=all_anomalies,
        summary=TimingAttackSummary(
            total_anomalies=len(all_anomalies),
            by_type=dict(by_type),
            critical_anomalies=by_sev.get("critical", 0),
            high_anomalies=by_sev.get("high", 0),
            agents_involved=len(agents),
            by_severity=dict(by_sev),
        ),
        agents_involved=agents,
    )


def format_text(report: TimingAttackReport) -> str:
    lines: list[str] = []
    lines.append("Timing Attack Pattern Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total anomalies:        {s.total_anomalies}")
    lines.append(f"  Critical anomalies:     {s.critical_anomalies}")
    lines.append(f"  High anomalies:         {s.high_anomalies}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if s.by_type:
        lines.append("  By Type:")
        for atype, count in sorted(s.by_type.items()):
            lines.append(f"    {atype}: {count}")
        lines.append("")

    if report.anomalies:
        lines.append("  Detected Anomalies:")
        lines.append("  " + "-" * 60)
        for a in report.anomalies:
            lines.append(f"  [{a.severity.upper()}] {a.anomaly_type}: {a.agent_id}")
            lines.append(f"    {a.description}")
            if a.resources:
                lines.append(f"    Resources: {', '.join(a.resources[:5])}")
            if a.related_agents:
                lines.append(f"    Related agents: {', '.join(a.related_agents)}")
            lines.append(f"    Duration: {a.duration_seconds:.1f}s  Source: {a.source_file}:{a.line}")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: TimingAttackReport) -> str:
    data = {
        "anomalies": [asdict(a) for a in report.anomalies],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
