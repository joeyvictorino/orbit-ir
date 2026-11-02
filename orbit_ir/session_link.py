"""Cross-session event linking for agent incident reconstruction.

Detects events that span multiple agent sessions—same agent appearing
across sessions, shared resources accessed from different sessions,
and temporal overlaps that suggest coordinated activity.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class SessionLink:
    link_id: str
    link_type: str  # "agent-overlap", "resource-shared", "temporal-overlap"
    sessions: list[str]
    agents: list[str]
    resources: list[str]
    timestamp_start: str
    timestamp_end: str
    confidence: str
    description: str


@dataclass
class SessionOverlap:
    session_a: str
    session_b: str
    overlap_start: str
    overlap_end: str
    shared_agents: list[str]
    shared_resources: list[str]


@dataclass
class SessionLinkSummary:
    total_links: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)
    sessions_analyzed: int = 0
    cross_session_agents: int = 0
    shared_resources: int = 0


@dataclass
class SessionLinkReport:
    links: list[SessionLink]
    overlaps: list[SessionOverlap]
    summary: SessionLinkSummary


def analyze_session_links(events: list[dict[str, Any]]) -> SessionLinkReport:
    session_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        session = ev.get("session_id", "")
        if session:
            session_events[session].append(ev)

    for evts in session_events.values():
        evts.sort(key=lambda e: e.get("timestamp", ""))

    links: list[SessionLink] = []
    overlaps: list[SessionOverlap] = []
    counter = 0

    counter = _detect_agent_overlaps(session_events, links, counter)
    counter = _detect_resource_sharing(session_events, links, counter)
    counter = _detect_temporal_overlaps(session_events, links, overlaps, counter)

    links.sort(key=lambda l: {"high": 0, "medium": 1, "low": 2}.get(l.confidence, 3))

    all_sessions = set()
    cross_agents = set()
    shared_resources = set()
    type_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)

    for l in links:
        all_sessions.update(l.sessions)
        cross_agents.update(l.agents)
        shared_resources.update(l.resources)
        type_counts[l.link_type] += 1
        conf_counts[l.confidence] += 1

    return SessionLinkReport(
        links=links,
        overlaps=overlaps,
        summary=SessionLinkSummary(
            total_links=len(links),
            by_type=dict(type_counts),
            by_confidence=dict(conf_counts),
            sessions_analyzed=len(session_events),
            cross_session_agents=len(cross_agents),
            shared_resources=len(shared_resources),
        ),
    )


def _detect_agent_overlaps(
    session_events: dict[str, list[dict[str, Any]]],
    links: list[SessionLink],
    counter: int,
) -> int:
    agent_sessions: dict[str, set[str]] = defaultdict(set)
    agent_timestamps: dict[str, list[str]] = defaultdict(list)

    for session, evts in session_events.items():
        for ev in evts:
            agent = ev.get("agent_id", "")
            if agent:
                agent_sessions[agent].add(session)
                ts = ev.get("timestamp", "")
                if ts:
                    agent_timestamps[agent].append(ts)

    for agent, sessions in sorted(agent_sessions.items()):
        if len(sessions) < 2:
            continue
        counter += 1
        timestamps = sorted(agent_timestamps.get(agent, []))
        confidence = "high" if len(sessions) >= 3 else "medium"

        links.append(SessionLink(
            link_id=f"SL-{counter:03d}",
            link_type="agent-overlap",
            sessions=sorted(sessions),
            agents=[agent],
            resources=[],
            timestamp_start=timestamps[0] if timestamps else "",
            timestamp_end=timestamps[-1] if timestamps else "",
            confidence=confidence,
            description=f"Agent '{agent}' appears in {len(sessions)} sessions: {', '.join(sorted(sessions)[:3])}",
        ))

    return counter


def _detect_resource_sharing(
    session_events: dict[str, list[dict[str, Any]]],
    links: list[SessionLink],
    counter: int,
) -> int:
    resource_sessions: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for session, evts in session_events.items():
        for ev in evts:
            resource = ev.get("resource", "")
            if resource:
                norm = resource.strip().lower()
                resource_sessions[norm]["sessions"].add(session)
                agent = ev.get("agent_id", "")
                if agent:
                    resource_sessions[norm]["agents"].add(agent)

    for resource, info in sorted(resource_sessions.items()):
        sessions = info.get("sessions", set())
        agents = info.get("agents", set())
        if len(sessions) < 2:
            continue
        counter += 1
        confidence = "high" if len(sessions) >= 3 else "medium"

        links.append(SessionLink(
            link_id=f"SL-{counter:03d}",
            link_type="resource-shared",
            sessions=sorted(sessions),
            agents=sorted(agents),
            resources=[resource],
            timestamp_start="",
            timestamp_end="",
            confidence=confidence,
            description=f"Resource '{resource}' accessed from {len(sessions)} sessions by {len(agents)} agent(s)",
        ))

    return counter


def _detect_temporal_overlaps(
    session_events: dict[str, list[dict[str, Any]]],
    links: list[SessionLink],
    overlaps: list[SessionOverlap],
    counter: int,
) -> int:
    session_ranges: dict[str, tuple[str, str]] = {}
    session_agents: dict[str, set[str]] = defaultdict(set)
    session_resources: dict[str, set[str]] = defaultdict(set)

    for session, evts in session_events.items():
        timestamps = [e.get("timestamp", "") for e in evts if e.get("timestamp")]
        if not timestamps:
            continue
        session_ranges[session] = (min(timestamps), max(timestamps))
        for ev in evts:
            agent = ev.get("agent_id", "")
            if agent:
                session_agents[session].add(agent)
            resource = ev.get("resource", "")
            if resource:
                session_resources[session].add(resource)

    sessions = sorted(session_ranges.keys())
    for i in range(len(sessions)):
        for j in range(i + 1, len(sessions)):
            sa, sb = sessions[i], sessions[j]
            start_a, end_a = session_ranges[sa]
            start_b, end_b = session_ranges[sb]

            overlap_start = max(start_a, start_b)
            overlap_end = min(end_a, end_b)
            if overlap_start > overlap_end:
                continue

            shared_agents = sorted(session_agents[sa] & session_agents[sb])
            shared_resources = sorted(session_resources[sa] & session_resources[sb])

            overlaps.append(SessionOverlap(
                session_a=sa,
                session_b=sb,
                overlap_start=overlap_start,
                overlap_end=overlap_end,
                shared_agents=shared_agents,
                shared_resources=shared_resources,
            ))

            if shared_agents or shared_resources:
                counter += 1
                confidence = "high" if shared_agents and shared_resources else "medium"
                links.append(SessionLink(
                    link_id=f"SL-{counter:03d}",
                    link_type="temporal-overlap",
                    sessions=[sa, sb],
                    agents=shared_agents,
                    resources=shared_resources,
                    timestamp_start=overlap_start,
                    timestamp_end=overlap_end,
                    confidence=confidence,
                    description=f"Sessions '{sa}' and '{sb}' overlap with {len(shared_agents)} shared agent(s) and {len(shared_resources)} shared resource(s)",
                ))

    return counter


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


def format_text(report: SessionLinkReport) -> str:
    lines: list[str] = []
    lines.append("Cross-Session Event Linking Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total links:            {s.total_links}")
    lines.append(f"  Sessions analyzed:      {s.sessions_analyzed}")
    lines.append(f"  Cross-session agents:   {s.cross_session_agents}")
    lines.append(f"  Shared resources:       {s.shared_resources}")
    lines.append("")

    if s.by_type:
        lines.append("  By Type:")
        for t, count in sorted(s.by_type.items()):
            lines.append(f"    {t}: {count}")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for c, count in sorted(s.by_confidence.items()):
            lines.append(f"    {c}: {count}")
        lines.append("")

    for l in report.links:
        lines.append(f"  [{l.confidence.upper()}] {l.link_id}: {l.link_type}")
        lines.append(f"    {l.description}")
        lines.append(f"    Sessions: {', '.join(l.sessions[:5])}")
        if l.agents:
            lines.append(f"    Agents: {', '.join(l.agents[:5])}")
        if l.resources:
            lines.append(f"    Resources: {', '.join(l.resources[:3])}")
        if l.timestamp_start:
            lines.append(f"    Time: {l.timestamp_start} -> {l.timestamp_end}")
        lines.append("")

    if report.overlaps:
        lines.append("  Session Overlaps:")
        lines.append("  " + "-" * 60)
        for o in report.overlaps:
            lines.append(f"    {o.session_a} <-> {o.session_b}")
            lines.append(f"      Window: {o.overlap_start} -> {o.overlap_end}")
            if o.shared_agents:
                lines.append(f"      Shared agents: {', '.join(o.shared_agents)}")
            if o.shared_resources:
                lines.append(f"      Shared resources: {', '.join(o.shared_resources[:3])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: SessionLinkReport) -> str:
    data = {
        "links": [asdict(l) for l in report.links],
        "overlaps": [asdict(o) for o in report.overlaps],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
