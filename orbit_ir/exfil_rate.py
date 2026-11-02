"""Exfiltration rate analysis for agent evidence.

Measures data transfer velocity and volume over time to detect burst
exfiltration, steady low-and-slow drip patterns, and acceleration in
outbound data movement. Produces per-agent rate profiles with anomaly
flags when transfer patterns exceed configurable thresholds.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


EXFIL_ACTIONS = {
    "upload", "send", "transmit", "export", "transfer", "post",
    "write_external", "push_data", "sync_external", "exfiltrate",
    "copy_out", "download_external",
}

DEFAULT_BURST_THRESHOLD = 10000
DEFAULT_WINDOW_SECONDS = 300


@dataclass
class TransferEvent:
    timestamp: str
    agent_id: str
    event_id: str
    action: str
    bytes_transferred: int
    destination: str
    source_file: str
    line: int


@dataclass
class RateAnomaly:
    anomaly_type: str
    agent_id: str
    window_start: str
    window_end: str
    bytes_in_window: int
    events_in_window: int
    rate_bytes_per_sec: float
    description: str


@dataclass
class AgentRateProfile:
    agent_id: str
    total_bytes: int
    total_events: int
    avg_bytes_per_event: float
    peak_rate_bytes_per_sec: float
    duration_seconds: float
    overall_rate_bytes_per_sec: float
    anomalies: list[RateAnomaly]
    transfers: list[TransferEvent]


@dataclass
class ExfilRateSummary:
    total_agents: int
    total_bytes: int
    total_events: int
    agents_with_anomalies: int
    burst_anomalies: int
    drip_anomalies: int
    acceleration_anomalies: int
    highest_rate_agent: str
    highest_rate_bytes_per_sec: float


@dataclass
class ExfilRateReport:
    profiles: list[AgentRateProfile]
    summary: ExfilRateSummary
    agents_with_anomalies: list[str]


def _parse_timestamp(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _is_exfil_action(tool: str) -> bool:
    lower = tool.lower()
    return any(kw in lower for kw in EXFIL_ACTIONS)


def _extract_bytes(ev: dict[str, Any]) -> int:
    for key in ("bytes_transferred", "size", "bytes", "content_length", "payload_size"):
        val = ev.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    response = ev.get("response", ev.get("output", ""))
    if isinstance(response, str):
        return len(response.encode("utf-8", errors="replace"))
    return 0


def _build_transfers(events: list[dict[str, Any]]) -> dict[str, list[TransferEvent]]:
    agent_transfers: dict[str, list[TransferEvent]] = defaultdict(list)

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
        if not _is_exfil_action(tool):
            continue

        xfer = TransferEvent(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("tool_call_id", ev.get("event_id", "")),
            action=tool,
            bytes_transferred=_extract_bytes(ev),
            destination=ev.get("destination", ev.get("resource", "")),
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", i + 1),
        )
        agent_transfers[agent].append(xfer)

    for transfers in agent_transfers.values():
        transfers.sort(key=lambda t: t.timestamp)

    return agent_transfers


def _detect_burst(
    transfers: list[TransferEvent],
    agent: str,
    window_sec: int,
    burst_threshold: int,
) -> list[RateAnomaly]:
    anomalies: list[RateAnomaly] = []
    if len(transfers) < 2:
        return anomalies

    parsed = []
    for t in transfers:
        dt = _parse_timestamp(t.timestamp)
        if dt is not None:
            parsed.append((dt, t))

    if len(parsed) < 2:
        return anomalies

    for i, (dt_i, t_i) in enumerate(parsed):
        window_bytes = t_i.bytes_transferred
        window_count = 1
        last_dt = dt_i

        for j in range(i + 1, len(parsed)):
            dt_j, t_j = parsed[j]
            delta = (dt_j - dt_i).total_seconds()
            if delta > window_sec:
                break
            window_bytes += t_j.bytes_transferred
            window_count += 1
            last_dt = dt_j

        if window_count >= 2 and window_bytes >= burst_threshold:
            span = max((last_dt - dt_i).total_seconds(), 1.0)
            rate = window_bytes / span
            anomalies.append(RateAnomaly(
                anomaly_type="burst",
                agent_id=agent,
                window_start=t_i.timestamp,
                window_end=transfers[min(i + window_count - 1, len(transfers) - 1)].timestamp,
                bytes_in_window=window_bytes,
                events_in_window=window_count,
                rate_bytes_per_sec=round(rate, 2),
                description=f"Burst: {window_bytes} bytes in {span:.0f}s ({window_count} events)",
            ))
            break

    return anomalies


def _detect_drip(
    transfers: list[TransferEvent],
    agent: str,
    min_events: int = 5,
    max_bytes_per_event: int = 500,
) -> list[RateAnomaly]:
    anomalies: list[RateAnomaly] = []
    if len(transfers) < min_events:
        return anomalies

    small = [t for t in transfers if t.bytes_transferred <= max_bytes_per_event]
    if len(small) < min_events:
        return anomalies

    total = sum(t.bytes_transferred for t in small)
    first_dt = _parse_timestamp(small[0].timestamp)
    last_dt = _parse_timestamp(small[-1].timestamp)
    if first_dt is None or last_dt is None:
        return anomalies

    span = max((last_dt - first_dt).total_seconds(), 1.0)
    rate = total / span

    anomalies.append(RateAnomaly(
        anomaly_type="drip",
        agent_id=agent,
        window_start=small[0].timestamp,
        window_end=small[-1].timestamp,
        bytes_in_window=total,
        events_in_window=len(small),
        rate_bytes_per_sec=round(rate, 2),
        description=f"Steady drip: {len(small)} small transfers ({total} bytes) over {span:.0f}s",
    ))
    return anomalies


def _detect_acceleration(
    transfers: list[TransferEvent],
    agent: str,
    min_events: int = 4,
) -> list[RateAnomaly]:
    anomalies: list[RateAnomaly] = []
    if len(transfers) < min_events:
        return anomalies

    parsed = []
    for t in transfers:
        dt = _parse_timestamp(t.timestamp)
        if dt is not None:
            parsed.append((dt, t))

    if len(parsed) < min_events:
        return anomalies

    intervals: list[float] = []
    for i in range(1, len(parsed)):
        delta = (parsed[i][0] - parsed[i - 1][0]).total_seconds()
        intervals.append(max(delta, 0.1))

    if len(intervals) < 3:
        return anomalies

    mid = len(intervals) // 2
    first_half = intervals[:mid]
    second_half = intervals[mid:]

    avg_first = sum(first_half) / len(first_half)
    avg_second = sum(second_half) / len(second_half)

    if avg_first > 0 and avg_second < avg_first * 0.5:
        first_dt = parsed[0][0]
        last_dt = parsed[-1][0]
        span = max((last_dt - first_dt).total_seconds(), 1.0)
        total = sum(t.bytes_transferred for _, t in parsed)
        rate = total / span

        anomalies.append(RateAnomaly(
            anomaly_type="acceleration",
            agent_id=agent,
            window_start=parsed[0][1].timestamp,
            window_end=parsed[-1][1].timestamp,
            bytes_in_window=total,
            events_in_window=len(parsed),
            rate_bytes_per_sec=round(rate, 2),
            description=f"Acceleration: inter-event interval shrank from {avg_first:.1f}s to {avg_second:.1f}s",
        ))

    return anomalies


def analyze_exfil_rates(
    events: list[dict[str, Any]],
    burst_threshold: int = DEFAULT_BURST_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> ExfilRateReport:
    agent_transfers = _build_transfers(events)

    profiles: list[AgentRateProfile] = []
    anomaly_agents: set[str] = set()
    burst_count = 0
    drip_count = 0
    accel_count = 0
    max_rate = 0.0
    max_rate_agent = ""

    for agent, transfers in sorted(agent_transfers.items()):
        if not transfers:
            continue

        total_bytes = sum(t.bytes_transferred for t in transfers)
        total_events = len(transfers)
        avg_bytes = total_bytes / total_events if total_events else 0.0

        first_dt = _parse_timestamp(transfers[0].timestamp)
        last_dt = _parse_timestamp(transfers[-1].timestamp)
        if first_dt and last_dt and first_dt != last_dt:
            duration = (last_dt - first_dt).total_seconds()
        else:
            duration = 0.0

        overall_rate = total_bytes / max(duration, 1.0)

        all_anomalies: list[RateAnomaly] = []
        all_anomalies.extend(_detect_burst(transfers, agent, window_seconds, burst_threshold))
        all_anomalies.extend(_detect_drip(transfers, agent))
        all_anomalies.extend(_detect_acceleration(transfers, agent))

        peak = overall_rate
        for a in all_anomalies:
            if a.rate_bytes_per_sec > peak:
                peak = a.rate_bytes_per_sec

        if all_anomalies:
            anomaly_agents.add(agent)
            for a in all_anomalies:
                if a.anomaly_type == "burst":
                    burst_count += 1
                elif a.anomaly_type == "drip":
                    drip_count += 1
                elif a.anomaly_type == "acceleration":
                    accel_count += 1

        if peak > max_rate:
            max_rate = peak
            max_rate_agent = agent

        profiles.append(AgentRateProfile(
            agent_id=agent,
            total_bytes=total_bytes,
            total_events=total_events,
            avg_bytes_per_event=round(avg_bytes, 1),
            peak_rate_bytes_per_sec=round(peak, 2),
            duration_seconds=round(duration, 1),
            overall_rate_bytes_per_sec=round(overall_rate, 2),
            anomalies=all_anomalies,
            transfers=transfers,
        ))

    profiles.sort(key=lambda p: p.peak_rate_bytes_per_sec, reverse=True)
    total_bytes = sum(p.total_bytes for p in profiles)
    total_events = sum(p.total_events for p in profiles)

    return ExfilRateReport(
        profiles=profiles,
        summary=ExfilRateSummary(
            total_agents=len(profiles),
            total_bytes=total_bytes,
            total_events=total_events,
            agents_with_anomalies=len(anomaly_agents),
            burst_anomalies=burst_count,
            drip_anomalies=drip_count,
            acceleration_anomalies=accel_count,
            highest_rate_agent=max_rate_agent,
            highest_rate_bytes_per_sec=round(max_rate, 2),
        ),
        agents_with_anomalies=sorted(anomaly_agents),
    )


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
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


def format_text(report: ExfilRateReport) -> str:
    lines: list[str] = []
    lines.append("Exfiltration Rate Analysis Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:           {s.total_agents}")
    lines.append(f"  Total bytes:            {s.total_bytes}")
    lines.append(f"  Total transfer events:  {s.total_events}")
    lines.append(f"  Agents with anomalies:  {s.agents_with_anomalies}")
    if s.highest_rate_agent:
        lines.append(f"  Highest rate agent:     {s.highest_rate_agent} ({s.highest_rate_bytes_per_sec:.2f} B/s)")
    lines.append("")

    if s.burst_anomalies or s.drip_anomalies or s.acceleration_anomalies:
        lines.append("  Anomaly breakdown:")
        lines.append(f"    Burst:         {s.burst_anomalies}")
        lines.append(f"    Drip:          {s.drip_anomalies}")
        lines.append(f"    Acceleration:  {s.acceleration_anomalies}")
        lines.append("")

    for p in report.profiles:
        lines.append(f"  Agent: {p.agent_id}")
        lines.append(f"    Total bytes: {p.total_bytes} | Events: {p.total_events}")
        lines.append(f"    Avg bytes/event: {p.avg_bytes_per_event:.1f}")
        lines.append(f"    Peak rate: {p.peak_rate_bytes_per_sec:.2f} B/s | Duration: {p.duration_seconds:.1f}s")
        if p.anomalies:
            lines.append(f"    Anomalies ({len(p.anomalies)}):")
            for a in p.anomalies:
                lines.append(f"      [{a.anomaly_type.upper()}] {a.description}")
                lines.append(f"        Window: {a.window_start} -> {a.window_end}")
                lines.append(f"        {a.bytes_in_window} bytes, {a.events_in_window} events, {a.rate_bytes_per_sec:.2f} B/s")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ExfilRateReport) -> str:
    data = {
        "profiles": [
            {
                **{k: v for k, v in asdict(p).items() if k not in ("anomalies", "transfers")},
                "anomalies": [asdict(a) for a in p.anomalies],
                "transfer_count": len(p.transfers),
            }
            for p in report.profiles
        ],
        "summary": asdict(report.summary),
        "agents_with_anomalies": report.agents_with_anomalies,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
