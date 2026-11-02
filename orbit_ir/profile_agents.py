"""Agent behavior profiling from evidence data."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def profile_agents(input_dir: str) -> dict[str, Any]:
    events = _load_events(input_dir)
    agents: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", ev.get("agent", "unknown"))
        agents[agent].append(ev)

    profiles = []
    for agent_id, agent_events in sorted(agents.items()):
        prof = _build_profile(agent_id, agent_events)
        profiles.append(prof)

    return {
        "total_agents": len(profiles),
        "total_events": len(events),
        "profiles": profiles,
    }


def _build_profile(agent_id: str, events: list[dict]) -> dict[str, Any]:
    tool_counts: Counter = Counter()
    action_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    timestamps = []

    for ev in events:
        tool = ev.get("tool_name", ev.get("tool", ""))
        if tool:
            tool_counts[tool] += 1

        action = ev.get("action", ev.get("event_type", ""))
        if action:
            action_counts[action] += 1

        sev = ev.get("severity", "")
        if sev:
            severity_counts[sev] += 1

        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    timestamps.sort()
    time_span = ""
    if len(timestamps) >= 2:
        time_span = f"{timestamps[0]} to {timestamps[-1]}"

    top_tools = [{"tool": t, "count": c} for t, c in tool_counts.most_common(10)]
    top_actions = [{"action": a, "count": c} for a, c in action_counts.most_common(10)]

    risk_score = _compute_risk(severity_counts, tool_counts, len(events))

    return {
        "agent_id": agent_id,
        "event_count": len(events),
        "unique_tools": len(tool_counts),
        "unique_actions": len(action_counts),
        "top_tools": top_tools,
        "top_actions": top_actions,
        "severity_distribution": dict(severity_counts),
        "time_span": time_span,
        "risk_score": risk_score,
    }


def _compute_risk(sev_counts: Counter, tool_counts: Counter, total: int) -> float:
    score = 0.0
    score += sev_counts.get("critical", 0) * 10.0
    score += sev_counts.get("high", 0) * 5.0
    score += sev_counts.get("medium", 0) * 2.0
    score += sev_counts.get("low", 0) * 0.5

    if len(tool_counts) > 10:
        score += 5.0

    if total > 100:
        score += min(total / 50.0, 10.0)

    return round(min(score, 100.0), 2)


def _load_events(input_dir: str) -> list[dict]:
    events = []
    p = Path(input_dir)
    for f in sorted(p.glob("*.jsonl")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for f in sorted(p.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                events.extend(data)
        except (json.JSONDecodeError, ValueError):
            continue
    return events


def format_profile_text(result: dict[str, Any]) -> str:
    lines = [
        f"Agent Behavior Profiles ({result['total_agents']} agents, {result['total_events']} events)\n",
    ]
    for p in result["profiles"]:
        lines.append(f"  Agent: {p['agent_id']}")
        lines.append(f"    Events: {p['event_count']}  Tools: {p['unique_tools']}  Actions: {p['unique_actions']}")
        lines.append(f"    Risk score: {p['risk_score']}")
        if p["top_tools"]:
            tools_str = ", ".join(f"{t['tool']}({t['count']})" for t in p["top_tools"][:5])
            lines.append(f"    Top tools: {tools_str}")
        if p["time_span"]:
            lines.append(f"    Time span: {p['time_span']}")
        lines.append("")

    return "\n".join(lines)
