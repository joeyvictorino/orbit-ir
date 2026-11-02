"""Event clustering for incident event logs.

Groups events into temporal clusters (bursts), identifies campaigns
spanning multiple agents, and scores cluster density and isolation.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class EventCluster:
    cluster_id: str
    events: list[dict] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    event_count: int = 0
    density: float = 0.0
    is_burst: bool = False


@dataclass
class Campaign:
    campaign_id: str
    clusters: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    total_events: int = 0
    span_seconds: float = 0.0


@dataclass
class EventClusterSummary:
    total_events: int
    total_clusters: int
    burst_clusters: int
    campaigns: int
    avg_cluster_size: float
    max_cluster_size: int
    agents_involved: int
    largest_campaign_events: int


@dataclass
class EventClusterReport:
    clusters: list[EventCluster]
    campaigns: list[Campaign]
    summary: EventClusterSummary


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


def _tool_id(ev: dict) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", ev.get("action", ""))))


def analyze_event_clusters(
    events: list[dict[str, Any]],
    gap_threshold_seconds: float = 60.0,
    burst_min_events: int = 5,
    burst_max_seconds: float = 30.0,
    campaign_gap_seconds: float = 300.0,
) -> EventClusterReport:
    timed: list[tuple[datetime, dict]] = []
    for ev in events:
        ts = _parse_ts(ev)
        if ts:
            timed.append((ts, ev))
    timed.sort(key=lambda x: x[0])

    clusters: list[EventCluster] = []
    current: list[tuple[datetime, dict]] = []

    for ts, ev in timed:
        if current and (ts - current[-1][0]).total_seconds() > gap_threshold_seconds:
            clusters.append(_build_cluster(len(clusters), current, burst_min_events, burst_max_seconds))
            current = []
        current.append((ts, ev))

    if current:
        clusters.append(_build_cluster(len(clusters), current, burst_min_events, burst_max_seconds))

    campaigns = _detect_campaigns(clusters, campaign_gap_seconds)

    all_agents = set()
    max_size = 0
    for c in clusters:
        all_agents.update(c.agents)
        if c.event_count > max_size:
            max_size = c.event_count

    largest_campaign = 0
    for camp in campaigns:
        if camp.total_events > largest_campaign:
            largest_campaign = camp.total_events

    avg_size = sum(c.event_count for c in clusters) / len(clusters) if clusters else 0.0

    return EventClusterReport(
        clusters=clusters,
        campaigns=campaigns,
        summary=EventClusterSummary(
            total_events=len(timed),
            total_clusters=len(clusters),
            burst_clusters=sum(1 for c in clusters if c.is_burst),
            campaigns=len(campaigns),
            avg_cluster_size=round(avg_size, 1),
            max_cluster_size=max_size,
            agents_involved=len(all_agents),
            largest_campaign_events=largest_campaign,
        ),
    )


def _build_cluster(
    idx: int,
    items: list[tuple[datetime, dict]],
    burst_min: int,
    burst_max: float,
) -> EventCluster:
    agents = sorted(set(_agent_id(ev) for _, ev in items))
    tools = sorted(set(t for _, ev in items if (t := _tool_id(ev))))
    start = items[0][0]
    end = items[-1][0]
    dur = (end - start).total_seconds()
    density = len(items) / dur if dur > 0 else float(len(items))
    is_burst = len(items) >= burst_min and dur <= burst_max

    return EventCluster(
        cluster_id=f"EC-{idx:04d}",
        agents=agents,
        tools=tools,
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        duration_seconds=round(dur, 2),
        event_count=len(items),
        density=round(density, 3),
        is_burst=is_burst,
    )


def _detect_campaigns(
    clusters: list[EventCluster],
    gap_seconds: float,
) -> list[Campaign]:
    if not clusters:
        return []

    agent_clusters: dict[str, list[EventCluster]] = defaultdict(list)
    for c in clusters:
        for a in c.agents:
            agent_clusters[a].append(c)

    campaigns: list[Campaign] = []
    seen: set[str] = set()

    for agent, clist in sorted(agent_clusters.items()):
        if len(clist) < 2:
            continue
        group: list[EventCluster] = []
        for c in clist:
            if c.cluster_id in seen:
                continue
            if group:
                prev_end = datetime.fromisoformat(group[-1].end_time)
                cur_start = datetime.fromisoformat(c.start_time)
                if (cur_start - prev_end).total_seconds() > gap_seconds:
                    if len(group) >= 2:
                        campaigns.append(_build_campaign(len(campaigns), group))
                        for g in group:
                            seen.add(g.cluster_id)
                    group = []
            group.append(c)
        if len(group) >= 2:
            campaigns.append(_build_campaign(len(campaigns), group))
            for g in group:
                seen.add(g.cluster_id)

    return campaigns


def _build_campaign(idx: int, clusters: list[EventCluster]) -> Campaign:
    all_agents = set()
    total = 0
    for c in clusters:
        all_agents.update(c.agents)
        total += c.event_count
    start = datetime.fromisoformat(clusters[0].start_time)
    end = datetime.fromisoformat(clusters[-1].end_time)
    span = (end - start).total_seconds()
    return Campaign(
        campaign_id=f"CAMP-{idx:04d}",
        clusters=[c.cluster_id for c in clusters],
        agents=sorted(all_agents),
        total_events=total,
        span_seconds=round(span, 2),
    )


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def format_text(report: EventClusterReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("Event Cluster Analysis")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"  Total events:          {s.total_events}")
    lines.append(f"  Clusters:              {s.total_clusters}")
    lines.append(f"  Burst clusters:        {s.burst_clusters}")
    lines.append(f"  Campaigns:             {s.campaigns}")
    lines.append(f"  Avg cluster size:      {s.avg_cluster_size}")
    lines.append(f"  Max cluster size:      {s.max_cluster_size}")
    lines.append(f"  Agents involved:       {s.agents_involved}")
    lines.append(f"  Largest campaign:      {s.largest_campaign_events} events")
    lines.append("")

    if report.clusters:
        lines.append("Clusters:")
        for c in report.clusters:
            burst_tag = " [BURST]" if c.is_burst else ""
            lines.append(f"  {c.cluster_id}: {c.event_count} events, {c.duration_seconds}s, density={c.density}{burst_tag}")
            lines.append(f"    Agents: {', '.join(c.agents)}")
            if c.tools:
                lines.append(f"    Tools:  {', '.join(c.tools[:5])}")
        lines.append("")

    if report.campaigns:
        lines.append("Campaigns:")
        for camp in report.campaigns:
            lines.append(f"  {camp.campaign_id}: {camp.total_events} events across {len(camp.clusters)} clusters, span={camp.span_seconds}s")
            lines.append(f"    Agents: {', '.join(camp.agents)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: EventClusterReport) -> str:
    data = {
        "clusters": [asdict(c) for c in report.clusters],
        "campaigns": [asdict(c) for c in report.campaigns],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
