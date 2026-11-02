"""Token usage pattern tracing across agent interactions.

Analyzes token consumption patterns to detect anomalous usage—
sudden spikes, unusual input/output ratios, sustained high-throughput
periods, and agents consuming disproportionate resources that may
indicate data exfiltration, resource abuse, or covert computation.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class TokenSnapshot:
    timestamp: str
    agent_id: str
    event_id: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    ratio: float


@dataclass
class TokenAnomaly:
    agent_id: str
    anomaly_type: str
    severity: str
    description: str
    snapshots: list[TokenSnapshot]
    z_score: float


@dataclass
class AgentTokenProfile:
    agent_id: str
    total_input: int
    total_output: int
    total_tokens: int
    event_count: int
    avg_input: float
    avg_output: float
    avg_ratio: float
    max_single_output: int
    std_dev_output: float


@dataclass
class TokenTraceSummary:
    total_agents: int
    total_events: int
    total_tokens_consumed: int
    anomaly_count: int
    by_severity: dict[str, int]
    highest_consumer: str
    highest_ratio_agent: str


@dataclass
class TokenTraceReport:
    profiles: list[AgentTokenProfile]
    anomalies: list[TokenAnomaly]
    summary: TokenTraceSummary
    agents_involved: list[str]


def _extract_tokens(ev: dict[str, Any]) -> tuple[int, int]:
    usage = ev.get("token_usage") or ev.get("usage")
    if isinstance(usage, dict) and usage:
        inp = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        out = usage.get("output_tokens", usage.get("completion_tokens", 0))
        return int(inp or 0), int(out or 0)
    inp = ev.get("input_tokens", ev.get("prompt_tokens", 0))
    out = ev.get("output_tokens", ev.get("completion_tokens", 0))
    return int(inp or 0), int(out or 0)


def _build_profile(agent: str, snapshots: list[TokenSnapshot]) -> AgentTokenProfile:
    total_in = sum(s.input_tokens for s in snapshots)
    total_out = sum(s.output_tokens for s in snapshots)
    total = total_in + total_out
    n = len(snapshots)

    outputs = [s.output_tokens for s in snapshots]
    avg_out = total_out / max(n, 1)
    avg_in = total_in / max(n, 1)

    ratios = [s.ratio for s in snapshots if s.input_tokens > 0]
    avg_ratio = sum(ratios) / max(len(ratios), 1) if ratios else 0.0

    variance = sum((o - avg_out) ** 2 for o in outputs) / max(n, 1)
    std_dev = math.sqrt(variance)

    return AgentTokenProfile(
        agent_id=agent,
        total_input=total_in,
        total_output=total_out,
        total_tokens=total,
        event_count=n,
        avg_input=round(avg_in, 1),
        avg_output=round(avg_out, 1),
        avg_ratio=round(avg_ratio, 3),
        max_single_output=max(outputs) if outputs else 0,
        std_dev_output=round(std_dev, 1),
    )


def _detect_spike_anomalies(
    agent: str,
    snapshots: list[TokenSnapshot],
    profile: AgentTokenProfile,
) -> list[TokenAnomaly]:
    anomalies: list[TokenAnomaly] = []
    if profile.event_count < 3 or profile.std_dev_output == 0:
        return anomalies

    spike_snaps = []
    for s in snapshots:
        z = (s.output_tokens - profile.avg_output) / profile.std_dev_output
        if z > 2.0:
            spike_snaps.append((s, z))

    if spike_snaps:
        severity = "high" if any(z > 3.0 for _, z in spike_snaps) else "medium"
        max_z = max(z for _, z in spike_snaps)
        anomalies.append(TokenAnomaly(
            agent_id=agent,
            anomaly_type="output-spike",
            severity=severity,
            description=(
                f"Agent '{agent}' had {len(spike_snaps)} output spike(s) "
                f"exceeding 2 std devs from mean (max z-score: {max_z:.2f})"
            ),
            snapshots=[s for s, _ in spike_snaps],
            z_score=round(max_z, 3),
        ))
    return anomalies


def _detect_ratio_anomalies(
    agent: str,
    snapshots: list[TokenSnapshot],
) -> list[TokenAnomaly]:
    anomalies: list[TokenAnomaly] = []
    high_ratio = [s for s in snapshots if s.ratio > 5.0 and s.input_tokens > 0]

    if len(high_ratio) >= 2:
        max_ratio = max(s.ratio for s in high_ratio)
        anomalies.append(TokenAnomaly(
            agent_id=agent,
            anomaly_type="high-output-ratio",
            severity="medium",
            description=(
                f"Agent '{agent}' had {len(high_ratio)} event(s) with output/input "
                f"ratio > 5.0 (max: {max_ratio:.1f}x), suggesting generated content"
            ),
            snapshots=high_ratio,
            z_score=round(max_ratio, 3),
        ))
    return anomalies


def _detect_sustained_high(
    agent: str,
    snapshots: list[TokenSnapshot],
    global_avg: float,
) -> list[TokenAnomaly]:
    anomalies: list[TokenAnomaly] = []
    if not snapshots or global_avg == 0:
        return anomalies

    agent_avg = sum(s.total_tokens for s in snapshots) / len(snapshots)
    if agent_avg > global_avg * 3 and len(snapshots) >= 3:
        anomalies.append(TokenAnomaly(
            agent_id=agent,
            anomaly_type="sustained-high-usage",
            severity="high",
            description=(
                f"Agent '{agent}' averaged {agent_avg:.0f} tokens/event, "
                f"{agent_avg / global_avg:.1f}x the global average of {global_avg:.0f}"
            ),
            snapshots=snapshots[:5],
            z_score=round(agent_avg / global_avg, 3),
        ))
    return anomalies


def analyze_token_trace(events: list[dict[str, Any]]) -> TokenTraceReport:
    agent_snapshots: dict[str, list[TokenSnapshot]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue

        inp, out = _extract_tokens(ev)
        if inp == 0 and out == 0:
            continue

        total = inp + out
        ratio = out / inp if inp > 0 else 0.0

        agent_snapshots[agent].append(TokenSnapshot(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ""),
            input_tokens=inp,
            output_tokens=out,
            total_tokens=total,
            ratio=round(ratio, 3),
        ))

    for snaps in agent_snapshots.values():
        snaps.sort(key=lambda s: s.timestamp)

    profiles = []
    for agent in sorted(agent_snapshots):
        profiles.append(_build_profile(agent, agent_snapshots[agent]))

    all_totals = [s.total_tokens for snaps in agent_snapshots.values() for s in snaps]
    global_avg = sum(all_totals) / max(len(all_totals), 1)

    anomalies: list[TokenAnomaly] = []
    for p in profiles:
        snaps = agent_snapshots[p.agent_id]
        anomalies.extend(_detect_spike_anomalies(p.agent_id, snaps, p))
        anomalies.extend(_detect_ratio_anomalies(p.agent_id, snaps))
        anomalies.extend(_detect_sustained_high(p.agent_id, snaps, global_avg))

    anomalies.sort(key=lambda a: {"high": 0, "medium": 1, "low": 2}.get(a.severity, 3))

    total_tokens = sum(p.total_tokens for p in profiles)
    total_events = sum(p.event_count for p in profiles)
    sev_counts: dict[str, int] = defaultdict(int)
    for a in anomalies:
        sev_counts[a.severity] += 1

    highest_consumer = max(profiles, key=lambda p: p.total_tokens).agent_id if profiles else ""
    highest_ratio = max(profiles, key=lambda p: p.avg_ratio).agent_id if profiles else ""

    return TokenTraceReport(
        profiles=profiles,
        anomalies=anomalies,
        summary=TokenTraceSummary(
            total_agents=len(profiles),
            total_events=total_events,
            total_tokens_consumed=total_tokens,
            anomaly_count=len(anomalies),
            by_severity=dict(sev_counts),
            highest_consumer=highest_consumer,
            highest_ratio_agent=highest_ratio,
        ),
        agents_involved=sorted(agent_snapshots.keys()),
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


def format_text(report: TokenTraceReport) -> str:
    lines: list[str] = []
    lines.append("Token Usage Trace Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:           {s.total_agents}")
    lines.append(f"  Total events:           {s.total_events}")
    lines.append(f"  Total tokens consumed:  {s.total_tokens_consumed:,}")
    lines.append(f"  Anomalies detected:     {s.anomaly_count}")
    if s.highest_consumer:
        lines.append(f"  Highest consumer:       {s.highest_consumer}")
    if s.highest_ratio_agent:
        lines.append(f"  Highest output ratio:   {s.highest_ratio_agent}")
    lines.append("")

    if report.profiles:
        lines.append("  Agent Profiles:")
        lines.append("  " + "-" * 60)
        for p in sorted(report.profiles, key=lambda x: x.total_tokens, reverse=True):
            lines.append(
                f"    {p.agent_id}: {p.total_tokens:,} tokens "
                f"({p.event_count} events, avg ratio {p.avg_ratio:.2f})"
            )
        lines.append("")

    if report.anomalies:
        lines.append("  Anomalies:")
        lines.append("  " + "-" * 60)
        for a in report.anomalies:
            lines.append(f"    [{a.severity.upper()}] {a.anomaly_type}: {a.agent_id}")
            lines.append(f"      {a.description}")
            lines.append(f"      z-score: {a.z_score}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: TokenTraceReport) -> str:
    data = {
        "profiles": [asdict(p) for p in report.profiles],
        "anomalies": [
            {
                "agent_id": a.agent_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "z_score": a.z_score,
                "snapshot_count": len(a.snapshots),
            }
            for a in report.anomalies
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
