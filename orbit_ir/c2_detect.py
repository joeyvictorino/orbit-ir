"""Command-and-control communication pattern detection for agent evidence.

Analyzes agent event sequences to detect C2-like patterns—periodic
beaconing, encoded payloads, dynamic endpoint resolution, and
command-response cycles.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


BEACON_KEYWORDS = {
    "heartbeat", "ping", "checkin", "check_in", "poll", "beacon",
    "keepalive", "keep_alive", "status_report", "phone_home",
}

ENCODING_INDICATORS = {
    "base64", "hex", "encode", "obfuscate", "encrypt", "cipher",
    "xor", "rot13", "compress", "pack", "marshal",
}

COMMAND_TOOLS = {
    "execute", "exec", "run_command", "shell", "eval",
    "invoke", "dispatch", "process_instruction",
}

NETWORK_TOOLS = {
    "http_get", "http_post", "http_put", "api_call", "fetch",
    "request", "webhook", "connect", "send", "receive",
    "dns_lookup", "resolve_host",
}


@dataclass
class BeaconDetection:
    agent_id: str
    endpoint: str
    interval_mean: float
    interval_stddev: float
    sample_count: int
    regularity_score: float
    timestamps: list[str]
    confidence: str


@dataclass
class CommandPattern:
    agent_id: str
    pattern_type: str
    receive_event: dict[str, Any]
    execute_events: list[dict[str, Any]]
    report_event: dict[str, Any] | None
    timestamp: str
    confidence: str
    description: str


@dataclass
class CommunicationChannel:
    agent_id: str
    endpoint: str
    direction: str
    event_count: int
    first_seen: str
    last_seen: str
    has_encoding: bool
    protocol: str


@dataclass
class C2Summary:
    total_beacon_detections: int
    total_command_patterns: int
    total_channels: int
    agents_involved: int
    by_confidence: dict[str, int]
    highest_regularity: float


@dataclass
class C2Report:
    beacon_detections: list[BeaconDetection]
    command_patterns: list[CommandPattern]
    communication_channels: list[CommunicationChannel]
    summary: C2Summary
    agents_involved: list[str]


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_network_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in NETWORK_TOOLS or any(k in lower for k in {"http", "fetch", "request", "api_call", "webhook", "dns"})


def _is_command_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in COMMAND_TOOLS or any(k in lower for k in {"exec", "shell", "eval", "invoke", "dispatch"})


def _is_beacon_like(tool: str, resource: str) -> bool:
    lower_tool = tool.lower()
    lower_res = resource.lower()
    return any(k in lower_tool or k in lower_res for k in BEACON_KEYWORDS)


def _has_encoding_indicator(event: dict[str, Any]) -> bool:
    for val in [event.get("tool", ""), event.get("resource", ""), event.get("effect", ""), str(event.get("payload", ""))]:
        lower = str(val).lower()
        if any(k in lower for k in ENCODING_INDICATORS):
            return True
    return False


def _compute_intervals(timestamps: list[str]) -> list[float]:
    parsed = []
    for ts in timestamps:
        dt = _parse_ts(ts)
        if dt:
            parsed.append(dt)
    parsed.sort()
    intervals = []
    for i in range(1, len(parsed)):
        diff = (parsed[i] - parsed[i - 1]).total_seconds()
        intervals.append(diff)
    return intervals


def _regularity_score(intervals: list[float]) -> float:
    if len(intervals) < 2:
        return 0.0
    mean = sum(intervals) / len(intervals)
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    stddev = math.sqrt(variance)
    cv = stddev / mean
    score = max(0.0, 1.0 - cv)
    return round(score, 3)


def analyze_c2(events: list[dict[str, Any]]) -> C2Report:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    beacon_detections: list[BeaconDetection] = []
    command_patterns: list[CommandPattern] = []
    channels: list[CommunicationChannel] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        _detect_beacons(agent, evts_sorted, beacon_detections)
        _detect_command_patterns(agent, evts_sorted, command_patterns)
        _detect_channels(agent, evts_sorted, channels)

    beacon_detections.sort(key=lambda b: b.regularity_score, reverse=True)

    all_agents = set()
    conf_counts: dict[str, int] = defaultdict(int)
    for b in beacon_detections:
        all_agents.add(b.agent_id)
        conf_counts[b.confidence] += 1
    for cp in command_patterns:
        all_agents.add(cp.agent_id)
        conf_counts[cp.confidence] += 1

    highest_reg = max((b.regularity_score for b in beacon_detections), default=0.0)

    return C2Report(
        beacon_detections=beacon_detections,
        command_patterns=command_patterns,
        communication_channels=channels,
        summary=C2Summary(
            total_beacon_detections=len(beacon_detections),
            total_command_patterns=len(command_patterns),
            total_channels=len(channels),
            agents_involved=len(all_agents),
            by_confidence=dict(conf_counts),
            highest_regularity=highest_reg,
        ),
        agents_involved=sorted(all_agents),
    )


def _detect_beacons(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[BeaconDetection],
) -> None:
    endpoint_calls: dict[str, list[str]] = defaultdict(list)
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("endpoint", ""))
        ts = ev.get("timestamp", "")
        if not ts:
            continue
        if _is_network_tool(tool) or _is_beacon_like(tool, resource):
            key = resource if resource else tool
            endpoint_calls[key].append(ts)

    for endpoint, timestamps in endpoint_calls.items():
        if len(timestamps) < 3:
            continue
        intervals = _compute_intervals(timestamps)
        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        reg_score = _regularity_score(intervals)

        if reg_score < 0.3:
            continue

        if reg_score >= 0.8:
            confidence = "high"
        elif reg_score >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        detections.append(BeaconDetection(
            agent_id=agent,
            endpoint=endpoint,
            interval_mean=round(mean_interval, 2),
            interval_stddev=round(stddev, 2),
            sample_count=len(timestamps),
            regularity_score=reg_score,
            timestamps=sorted(timestamps),
            confidence=confidence,
        ))


def _detect_command_patterns(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[CommandPattern],
) -> None:
    i = 0
    while i < len(events):
        ev = events[i]
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))

        if _is_network_tool(tool) and ev.get("direction", "") in ("inbound", "receive", ""):
            exec_events: list[dict[str, Any]] = []
            report_ev = None

            j = i + 1
            while j < len(events) and j < i + 10:
                next_tool = events[j].get("tool", events[j].get("claimed_tool", events[j].get("actual_tool", "")))
                if _is_command_tool(next_tool):
                    exec_events.append(events[j])
                elif _is_network_tool(next_tool) and events[j].get("direction", "") in ("outbound", "send", "response", ""):
                    if exec_events:
                        report_ev = events[j]
                        break
                j += 1

            if exec_events:
                confidence = "high" if report_ev else "medium"
                desc_parts = [f"received instruction via {tool}"]
                desc_parts.append(f"executed {len(exec_events)} command(s)")
                if report_ev:
                    desc_parts.append("reported results back")

                patterns.append(CommandPattern(
                    agent_id=agent,
                    pattern_type="command-response" if report_ev else "command-execute",
                    receive_event=ev,
                    execute_events=exec_events,
                    report_event=report_ev,
                    timestamp=ev.get("timestamp", ""),
                    confidence=confidence,
                    description=f"Agent '{agent}' " + ", ".join(desc_parts),
                ))
                i = j + 1 if report_ev else j
                continue
        i += 1


def _detect_channels(
    agent: str,
    events: list[dict[str, Any]],
    channels: list[CommunicationChannel],
) -> None:
    endpoint_info: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "count": 0, "first": "", "last": "", "has_encoding": False, "directions": set(),
    })

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_network_tool(tool):
            continue
        endpoint = ev.get("resource", ev.get("endpoint", tool))
        ts = ev.get("timestamp", "")
        direction = ev.get("direction", "unknown")

        info = endpoint_info[endpoint]
        info["count"] += 1
        if not info["first"] or ts < info["first"]:
            info["first"] = ts
        if not info["last"] or ts > info["last"]:
            info["last"] = ts
        if _has_encoding_indicator(ev):
            info["has_encoding"] = True
        info["directions"].add(direction)

    for endpoint, info in sorted(endpoint_info.items()):
        if info["count"] < 2:
            continue
        dirs = info["directions"]
        if {"inbound", "outbound"} <= dirs or {"receive", "send"} <= dirs:
            direction = "bidirectional"
        elif "outbound" in dirs or "send" in dirs:
            direction = "outbound"
        elif "inbound" in dirs or "receive" in dirs:
            direction = "inbound"
        else:
            direction = "unknown"

        protocol = "https" if "http" in endpoint.lower() else "dns" if "dns" in endpoint.lower() else "unknown"

        channels.append(CommunicationChannel(
            agent_id=agent,
            endpoint=endpoint,
            direction=direction,
            event_count=info["count"],
            first_seen=info["first"],
            last_seen=info["last"],
            has_encoding=info["has_encoding"],
            protocol=protocol,
        ))


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for name in ("transcripts.jsonl", "control_plane.jsonl", "events.jsonl"):
        p = evidence_dir / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events


def format_text(report: C2Report) -> str:
    lines: list[str] = []
    lines.append("Command-and-Control Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Beacon detections:      {s.total_beacon_detections}")
    lines.append(f"  Command patterns:       {s.total_command_patterns}")
    lines.append(f"  Communication channels: {s.total_channels}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Highest regularity:     {s.highest_regularity}")
    lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    if report.beacon_detections:
        lines.append("  Beacon Detections:")
        lines.append("  " + "-" * 58)
        for b in report.beacon_detections:
            lines.append(f"    [{b.confidence.upper()}] {b.agent_id} -> {b.endpoint}")
            lines.append(f"      Interval: {b.interval_mean}s (stddev: {b.interval_stddev}s)")
            lines.append(f"      Regularity: {b.regularity_score} ({b.sample_count} samples)")
        lines.append("")

    if report.command_patterns:
        lines.append("  Command Patterns:")
        lines.append("  " + "-" * 58)
        for cp in report.command_patterns:
            lines.append(f"    [{cp.confidence.upper()}] {cp.agent_id}: {cp.pattern_type}")
            lines.append(f"      {cp.description}")
            lines.append(f"      Time: {cp.timestamp}")
        lines.append("")

    if report.communication_channels:
        lines.append("  Communication Channels:")
        lines.append("  " + "-" * 58)
        for ch in report.communication_channels:
            enc = " [ENCODED]" if ch.has_encoding else ""
            lines.append(f"    {ch.agent_id} <-> {ch.endpoint} ({ch.direction}{enc})")
            lines.append(f"      Events: {ch.event_count}, Protocol: {ch.protocol}")
            lines.append(f"      Period: {ch.first_seen} to {ch.last_seen}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: C2Report) -> str:
    data = {
        "beacon_detections": [asdict(b) for b in report.beacon_detections],
        "command_patterns": [
            {
                "agent_id": cp.agent_id,
                "pattern_type": cp.pattern_type,
                "receive_event": cp.receive_event,
                "execute_events": cp.execute_events,
                "report_event": cp.report_event,
                "timestamp": cp.timestamp,
                "confidence": cp.confidence,
                "description": cp.description,
            }
            for cp in report.command_patterns
        ],
        "communication_channels": [asdict(ch) for ch in report.communication_channels],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
