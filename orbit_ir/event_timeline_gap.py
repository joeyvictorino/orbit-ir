"""Event timeline gap detection for agent evidence.

Identifies suspicious gaps in event timelines that may indicate
log tampering, system downtime, or covert activity periods.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class TimelineGap:
    gap_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    agents_before: list[str]
    agents_after: list[str]
    events_before: int
    events_after: int
    severity: str


@dataclass
class AgentGap:
    agent_id: str
    gaps: int
    total_gap_seconds: float
    longest_gap_seconds: float
    avg_gap_seconds: float


@dataclass
class TimelineGapSummary:
    total_events: int
    total_gaps: int
    critical_gaps: int
    warning_gaps: int
    info_gaps: int
    longest_gap_seconds: float
    avg_gap_seconds: float
    total_gap_seconds: float
    agents_with_gaps: int
    timeline_coverage: float


@dataclass
class TimelineGapReport:
    gaps: list[TimelineGap]
    agent_gaps: list[AgentGap]
    summary: TimelineGapSummary


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


def _severity(duration: float, median_gap: float) -> str:
    if duration > median_gap * 10:
        return "critical"
    if duration > median_gap * 5:
        return "warning"
    return "info"


def analyze_timeline_gaps(
    events: list[dict[str, Any]],
    min_gap_seconds: float = 300.0,
) -> TimelineGapReport:
    timed: list[tuple[datetime, dict]] = []
    for ev in events:
        ts = _parse_ts(ev)
        if ts:
            timed.append((ts, ev))
    timed.sort(key=lambda x: x[0])

    if len(timed) < 2:
        return TimelineGapReport(
            gaps=[],
            agent_gaps=[],
            summary=TimelineGapSummary(
                total_events=len(timed),
                total_gaps=0,
                critical_gaps=0,
                warning_gaps=0,
                info_gaps=0,
                longest_gap_seconds=0.0,
                avg_gap_seconds=0.0,
                total_gap_seconds=0.0,
                agents_with_gaps=0,
                timeline_coverage=1.0,
            ),
        )

    all_inter = []
    for i in range(len(timed) - 1):
        gap = (timed[i + 1][0] - timed[i][0]).total_seconds()
        if gap > 0:
            all_inter.append(gap)

    median_gap = statistics.median(all_inter) if all_inter else 1.0

    gaps: list[TimelineGap] = []
    for i in range(len(timed) - 1):
        dur = (timed[i + 1][0] - timed[i][0]).total_seconds()
        if dur >= min_gap_seconds:
            window = 5
            before_agents = sorted(set(_agent_id(ev) for _, ev in timed[max(0, i - window + 1):i + 1]))
            after_agents = sorted(set(_agent_id(ev) for _, ev in timed[i + 1:i + 1 + window]))
            gaps.append(TimelineGap(
                gap_id=f"GAP-{len(gaps):04d}",
                start_time=timed[i][0].isoformat(),
                end_time=timed[i + 1][0].isoformat(),
                duration_seconds=round(dur, 2),
                agents_before=before_agents,
                agents_after=after_agents,
                events_before=i + 1,
                events_after=len(timed) - i - 1,
                severity=_severity(dur, median_gap),
            ))

    agent_gap_map: dict[str, list[float]] = defaultdict(list)
    by_agent: dict[str, list[datetime]] = defaultdict(list)
    for ts, ev in timed:
        by_agent[_agent_id(ev)].append(ts)

    for agent, timestamps in by_agent.items():
        timestamps.sort()
        for i in range(len(timestamps) - 1):
            dur = (timestamps[i + 1] - timestamps[i]).total_seconds()
            if dur >= min_gap_seconds:
                agent_gap_map[agent].append(dur)

    agent_gaps: list[AgentGap] = []
    for agent, glist in sorted(agent_gap_map.items()):
        agent_gaps.append(AgentGap(
            agent_id=agent,
            gaps=len(glist),
            total_gap_seconds=round(sum(glist), 2),
            longest_gap_seconds=round(max(glist), 2),
            avg_gap_seconds=round(statistics.mean(glist), 2),
        ))
    agent_gaps.sort(key=lambda a: a.total_gap_seconds, reverse=True)

    total_span = (timed[-1][0] - timed[0][0]).total_seconds()
    total_gap = sum(g.duration_seconds for g in gaps)
    coverage = 1.0 - (total_gap / total_span) if total_span > 0 else 1.0

    gap_durs = [g.duration_seconds for g in gaps]
    crit = sum(1 for g in gaps if g.severity == "critical")
    warn = sum(1 for g in gaps if g.severity == "warning")
    info = sum(1 for g in gaps if g.severity == "info")

    return TimelineGapReport(
        gaps=gaps,
        agent_gaps=agent_gaps,
        summary=TimelineGapSummary(
            total_events=len(timed),
            total_gaps=len(gaps),
            critical_gaps=crit,
            warning_gaps=warn,
            info_gaps=info,
            longest_gap_seconds=round(max(gap_durs), 2) if gap_durs else 0.0,
            avg_gap_seconds=round(statistics.mean(gap_durs), 2) if gap_durs else 0.0,
            total_gap_seconds=round(total_gap, 2),
            agents_with_gaps=len(agent_gaps),
            timeline_coverage=round(max(coverage, 0.0), 4),
        ),
    )


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def format_text(report: TimelineGapReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("Event Timeline Gap Analysis")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"  Total events:          {s.total_events}")
    lines.append(f"  Gaps detected:         {s.total_gaps}")
    lines.append(f"  Critical:              {s.critical_gaps}")
    lines.append(f"  Warning:               {s.warning_gaps}")
    lines.append(f"  Info:                  {s.info_gaps}")
    lines.append(f"  Longest gap:           {s.longest_gap_seconds}s")
    lines.append(f"  Avg gap:               {s.avg_gap_seconds}s")
    lines.append(f"  Total gap time:        {s.total_gap_seconds}s")
    lines.append(f"  Timeline coverage:     {s.timeline_coverage:.1%}")
    lines.append(f"  Agents with gaps:      {s.agents_with_gaps}")
    lines.append("")

    if report.gaps:
        lines.append("Gaps:")
        for g in report.gaps:
            sev_tag = f" [{g.severity.upper()}]"
            lines.append(f"  {g.gap_id}: {g.duration_seconds}s{sev_tag}")
            lines.append(f"    {g.start_time} -> {g.end_time}")
            lines.append(f"    Before: {', '.join(g.agents_before)}  After: {', '.join(g.agents_after)}")
        lines.append("")

    if report.agent_gaps:
        lines.append("Agent Gaps:")
        for a in report.agent_gaps:
            lines.append(f"  {a.agent_id}: {a.gaps} gaps, total={a.total_gap_seconds}s, longest={a.longest_gap_seconds}s")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: TimelineGapReport) -> str:
    data = {
        "gaps": [asdict(g) for g in report.gaps],
        "agent_gaps": [asdict(a) for a in report.agent_gaps],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
