"""Per-session summary statistics from agent evidence."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


EVIDENCE_FILES = ("transcripts.jsonl", "control_plane.jsonl", "events.jsonl")

TIMESTAMP_FMTS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
)


@dataclass
class SessionSummary:
    session_id: str
    event_count: int = 0
    agent_count: int = 0
    agents: list[str] = field(default_factory=list)
    unique_resources: int = 0
    unique_tools: int = 0
    action_types: dict[str, int] = field(default_factory=dict)
    first_event: str = ""
    last_event: str = ""
    duration_seconds: float = 0.0
    top_resources: list[str] = field(default_factory=list)
    top_tools: list[str] = field(default_factory=list)


@dataclass
class SessionStatsReport:
    total_sessions: int = 0
    total_events: int = 0
    sessions: list[SessionSummary] = field(default_factory=list)


def analyze(evidence_dir: Path) -> SessionStatsReport:
    events = _load_events(evidence_dir)
    if not events:
        return SessionStatsReport()

    sessions: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        sid = str(ev.get("session_id", ev.get("run_id", ev.get("trace_id", "default"))))
        sessions[sid].append(ev)

    summaries: list[SessionSummary] = []
    for sid, evs in sorted(sessions.items()):
        summaries.append(_summarize_session(sid, evs))

    summaries.sort(key=lambda s: s.event_count, reverse=True)

    return SessionStatsReport(
        total_sessions=len(summaries),
        total_events=len(events),
        sessions=summaries,
    )


def _summarize_session(session_id: str, events: list[dict]) -> SessionSummary:
    agents: set[str] = set()
    resources: set[str] = set()
    tools: set[str] = set()
    actions: dict[str, int] = defaultdict(int)
    timestamps: list[datetime] = []

    for ev in events:
        for k in ("agent_id", "agent", "user", "identity"):
            if k in ev and ev[k]:
                agents.add(str(ev[k]))

        res = ev.get("resource", ev.get("path", ""))
        if res:
            resources.add(str(res))

        tool = ev.get("tool", "")
        if tool:
            tools.add(str(tool))

        action = ev.get("action", ev.get("type", ""))
        if action:
            actions[str(action)] += 1

        ts = ev.get("timestamp", "")
        if ts:
            dt = _parse_ts(str(ts))
            if dt:
                timestamps.append(dt)

    timestamps.sort()
    first = timestamps[0].isoformat() + "Z" if timestamps else ""
    last = timestamps[-1].isoformat() + "Z" if timestamps else ""
    duration = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0.0

    res_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        r = ev.get("resource", ev.get("path", ""))
        if r:
            res_counts[str(r)] += 1
    top_res = sorted(res_counts, key=res_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

    tool_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        t = ev.get("tool", "")
        if t:
            tool_counts[str(t)] += 1
    top_tools = sorted(tool_counts, key=tool_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

    return SessionSummary(
        session_id=session_id,
        event_count=len(events),
        agent_count=len(agents),
        agents=sorted(agents),
        unique_resources=len(resources),
        unique_tools=len(tools),
        action_types=dict(actions),
        first_event=first,
        last_event=last,
        duration_seconds=round(duration, 2),
        top_resources=top_res,
        top_tools=top_tools,
    )


def _parse_ts(ts: str) -> datetime | None:
    for fmt in TIMESTAMP_FMTS:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    stripped = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(stripped[:26], fmt)
        except ValueError:
            pass
    return None


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for name in EVIDENCE_FILES:
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


def format_text(report: SessionStatsReport) -> str:
    lines: list[str] = []
    lines.append("Session Statistics Report")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Total sessions: {report.total_sessions}")
    lines.append(f"  Total events: {report.total_events}")
    lines.append("")

    for s in report.sessions:
        lines.append(f"  Session: {s.session_id}")
        lines.append(f"    Events: {s.event_count}")
        lines.append(f"    Agents: {s.agent_count} ({', '.join(s.agents)})")
        lines.append(f"    Unique resources: {s.unique_resources}")
        lines.append(f"    Unique tools: {s.unique_tools}")
        if s.duration_seconds > 0:
            lines.append(f"    Duration: {s.duration_seconds}s")
        if s.first_event:
            lines.append(f"    Time range: {s.first_event} -> {s.last_event}")
        if s.action_types:
            actions_str = ", ".join(f"{k}={v}" for k, v in sorted(s.action_types.items()))
            lines.append(f"    Actions: {actions_str}")
        if s.top_resources:
            lines.append(f"    Top resources: {', '.join(s.top_resources[:3])}")
        if s.top_tools:
            lines.append(f"    Top tools: {', '.join(s.top_tools[:3])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: SessionStatsReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=False) + "\n"
