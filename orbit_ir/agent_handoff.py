"""Agent handoff pattern analysis for incident event logs.

Analyzes task handoff patterns between agents including handoff
frequency, latency, chain depth, and dropped handoffs.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Handoff:
    handoff_id: str
    from_agent: str
    to_agent: str
    timestamp: str
    latency_seconds: float
    context_type: str


@dataclass
class HandoffChain:
    chain_id: str
    agents: list[str]
    depth: int
    total_latency_seconds: float
    start_time: str
    end_time: str


@dataclass
class AgentHandoffProfile:
    agent_id: str
    handoffs_out: int
    handoffs_in: int
    avg_outbound_latency: float
    top_targets: list[str]
    dropped: int


@dataclass
class HandoffSummary:
    total_handoffs: int
    unique_agent_pairs: int
    agents_involved: int
    avg_latency_seconds: float
    max_chain_depth: int
    dropped_handoffs: int
    busiest_pair: str
    busiest_pair_count: int


@dataclass
class HandoffReport:
    handoffs: list[Handoff]
    chains: list[HandoffChain]
    profiles: list[AgentHandoffProfile]
    summary: HandoffSummary


def _parse_ts(ev: dict) -> datetime | None:
    for k in ("timestamp", "ts", "time", "date", "created_at"):
        val = ev.get(k)
        if val:
            try:
                return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
    return None


def _agent_id(ev: dict) -> str:
    return ev.get("agent", ev.get("agent_id", ev.get("source", "unknown")))


def analyze_handoffs(
    events: list[dict[str, Any]],
    handoff_gap_seconds: float = 5.0,
) -> HandoffReport:
    timed: list[tuple[datetime, dict]] = []
    for ev in events:
        ts = _parse_ts(ev)
        if ts:
            timed.append((ts, ev))
    timed.sort(key=lambda x: x[0])

    handoffs: list[Handoff] = []
    pair_counts: Counter = Counter()
    agent_out: dict[str, list[float]] = defaultdict(list)
    agent_in: dict[str, int] = Counter()
    agent_targets: dict[str, Counter] = defaultdict(Counter)
    all_agents: set[str] = set()

    for i in range(len(timed) - 1):
        ts1, ev1 = timed[i]
        ts2, ev2 = timed[i + 1]
        a1 = _agent_id(ev1)
        a2 = _agent_id(ev2)
        all_agents.add(a1)
        all_agents.add(a2)

        if a1 != a2:
            latency = (ts2 - ts1).total_seconds()
            ctx = ev2.get("type", ev2.get("event_type", "unknown"))
            handoffs.append(Handoff(
                handoff_id=f"HO-{len(handoffs):04d}",
                from_agent=a1,
                to_agent=a2,
                timestamp=ts1.isoformat(),
                latency_seconds=round(latency, 2),
                context_type=ctx,
            ))
            pair = (a1, a2)
            pair_counts[pair] += 1
            agent_out[a1].append(latency)
            agent_in[a2] += 1
            agent_targets[a1][a2] += 1

    chains = _build_chains(handoffs, handoff_gap_seconds)

    dropped = 0
    agent_dropped: dict[str, int] = Counter()
    for i, ho in enumerate(handoffs):
        if ho.latency_seconds > handoff_gap_seconds * 10:
            dropped += 1
            agent_dropped[ho.from_agent] += 1

    profiles: list[AgentHandoffProfile] = []
    for agent in sorted(all_agents):
        out_lats = agent_out.get(agent, [])
        avg_lat = round(sum(out_lats) / len(out_lats), 2) if out_lats else 0.0
        targets = [t for t, _ in agent_targets.get(agent, Counter()).most_common(3)]
        profiles.append(AgentHandoffProfile(
            agent_id=agent,
            handoffs_out=len(out_lats),
            handoffs_in=agent_in.get(agent, 0),
            avg_outbound_latency=avg_lat,
            top_targets=targets,
            dropped=agent_dropped.get(agent, 0),
        ))
    profiles.sort(key=lambda p: p.handoffs_out + p.handoffs_in, reverse=True)

    busiest = pair_counts.most_common(1)
    busiest_str = f"{busiest[0][0][0]} -> {busiest[0][0][1]}" if busiest else ""
    busiest_cnt = busiest[0][1] if busiest else 0

    lats = [h.latency_seconds for h in handoffs]
    avg_lat = round(sum(lats) / len(lats), 2) if lats else 0.0
    max_depth = max((c.depth for c in chains), default=0)

    return HandoffReport(
        handoffs=handoffs,
        chains=chains,
        profiles=profiles,
        summary=HandoffSummary(
            total_handoffs=len(handoffs),
            unique_agent_pairs=len(pair_counts),
            agents_involved=len(all_agents),
            avg_latency_seconds=avg_lat,
            max_chain_depth=max_depth,
            dropped_handoffs=dropped,
            busiest_pair=busiest_str,
            busiest_pair_count=busiest_cnt,
        ),
    )


def _build_chains(handoffs: list[Handoff], gap: float) -> list[HandoffChain]:
    if not handoffs:
        return []

    chains: list[HandoffChain] = []
    current: list[Handoff] = [handoffs[0]]

    for ho in handoffs[1:]:
        prev = current[-1]
        if ho.from_agent == prev.to_agent and ho.latency_seconds <= gap * 10:
            current.append(ho)
        else:
            if len(current) >= 2:
                chains.append(_finalize_chain(len(chains), current))
            current = [ho]

    if len(current) >= 2:
        chains.append(_finalize_chain(len(chains), current))

    return chains


def _finalize_chain(idx: int, handoffs: list[Handoff]) -> HandoffChain:
    agents = [handoffs[0].from_agent]
    for ho in handoffs:
        agents.append(ho.to_agent)
    total_lat = sum(h.latency_seconds for h in handoffs)
    return HandoffChain(
        chain_id=f"HC-{idx:04d}",
        agents=agents,
        depth=len(agents),
        total_latency_seconds=round(total_lat, 2),
        start_time=handoffs[0].timestamp,
        end_time=handoffs[-1].timestamp,
    )


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def format_text(report: HandoffReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("Agent Handoff Analysis")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"  Total handoffs:        {s.total_handoffs}")
    lines.append(f"  Unique pairs:          {s.unique_agent_pairs}")
    lines.append(f"  Agents involved:       {s.agents_involved}")
    lines.append(f"  Avg latency:           {s.avg_latency_seconds}s")
    lines.append(f"  Max chain depth:       {s.max_chain_depth}")
    lines.append(f"  Dropped handoffs:      {s.dropped_handoffs}")
    if s.busiest_pair:
        lines.append(f"  Busiest pair:          {s.busiest_pair} ({s.busiest_pair_count}x)")
    lines.append("")

    if report.chains:
        lines.append("Handoff Chains:")
        for c in report.chains[:10]:
            lines.append(f"  {c.chain_id}: {' -> '.join(c.agents)} (depth={c.depth}, latency={c.total_latency_seconds}s)")
        lines.append("")

    if report.profiles:
        lines.append("Agent Profiles:")
        for p in report.profiles[:10]:
            lines.append(f"  {p.agent_id}: out={p.handoffs_out} in={p.handoffs_in} avg_lat={p.avg_outbound_latency}s dropped={p.dropped}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: HandoffReport) -> str:
    data = {
        "handoffs": [asdict(h) for h in report.handoffs],
        "chains": [asdict(c) for c in report.chains],
        "profiles": [asdict(p) for p in report.profiles],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
