"""Agent risk ranking based on event pattern analysis."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


_DEFAULT_WEIGHTS = {
    "volume": 0.15,
    "type_diversity": 0.20,
    "tool_diversity": 0.20,
    "error_rate": 0.25,
    "anomaly_score": 0.20,
}


def _compute_agent_scores(
    events: list[dict[str, Any]],
    weights: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    w = dict(_DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)

    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        aid = ev.get("agent_id")
        if aid:
            agent_events[aid].append(ev)

    if not agent_events:
        return []

    max_volume = max(len(evs) for evs in agent_events.values()) or 1

    results: list[dict[str, Any]] = []
    for aid, evs in agent_events.items():
        volume = len(evs)
        types = set()
        tools = set()
        errors = 0
        anomalies = 0

        for ev in evs:
            etype = ev.get("event_type") or ev.get("type", "")
            types.add(etype)
            if etype in ("tool_call", "tool_use"):
                tool = ev.get("tool") or ev.get("tool_name") or ev.get("name", "")
                if tool:
                    tools.add(tool)
            if etype in ("error", "failure", "exception"):
                errors += 1
            if ev.get("anomaly") or ev.get("severity") in ("high", "critical"):
                anomalies += 1

        volume_score = volume / max_volume
        type_div = min(len(types) / 10.0, 1.0)
        tool_div = min(len(tools) / 8.0, 1.0)
        error_rate = errors / volume if volume else 0.0
        anomaly_score = min(anomalies / max(volume * 0.1, 1), 1.0)

        composite = (
            w["volume"] * volume_score
            + w["type_diversity"] * type_div
            + w["tool_diversity"] * tool_div
            + w["error_rate"] * error_rate
            + w["anomaly_score"] * anomaly_score
        )

        results.append({
            "agent_id": aid,
            "event_count": volume,
            "unique_types": len(types),
            "unique_tools": len(tools),
            "error_count": errors,
            "anomaly_count": anomalies,
            "scores": {
                "volume": round(volume_score, 4),
                "type_diversity": round(type_div, 4),
                "tool_diversity": round(tool_div, 4),
                "error_rate": round(error_rate, 4),
                "anomaly_score": round(anomaly_score, 4),
            },
            "composite": round(composite, 4),
        })

    return results


def rank_agents(
    path: Path,
    *,
    sort_by: str = "risk",
    top_n: int | None = None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    events = load_events(path)
    agents = _compute_agent_scores(events, weights)

    if sort_by == "volume":
        agents.sort(key=lambda a: a["event_count"], reverse=True)
    elif sort_by == "diversity":
        agents.sort(key=lambda a: a["unique_types"] + a["unique_tools"], reverse=True)
    else:
        agents.sort(key=lambda a: a["composite"], reverse=True)

    if top_n is not None:
        agents = agents[:top_n]

    return {
        "total_events": len(events),
        "total_agents": len(agents),
        "sort_by": sort_by,
        "weights": weights or _DEFAULT_WEIGHTS,
        "agents": agents,
    }


def format_rank_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Agent Risk Ranking (sort={result['sort_by']})")
    lines.append(f"Total events: {result['total_events']}  Agents: {result['total_agents']}\n")

    if not result["agents"]:
        lines.append("  No agents found.\n")
        return "\n".join(lines)

    header = f"{'Rank':<6}{'Agent':<16}{'Events':<8}{'Types':<7}{'Tools':<7}{'Errors':<8}{'Score':<8}"
    lines.append(header)
    lines.append("-" * len(header))

    for i, a in enumerate(result["agents"], 1):
        line = (
            f"{i:<6}"
            f"{a['agent_id']:<16}"
            f"{a['event_count']:<8}"
            f"{a['unique_types']:<7}"
            f"{a['unique_tools']:<7}"
            f"{a['error_count']:<8}"
            f"{a['composite']:<8.4f}"
        )
        lines.append(line)

    lines.append("")
    return "\n".join(lines)
