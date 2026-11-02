"""Behavioral delta analysis between two agents."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .timeline import build_timeline


def diff_agents(
    input_path: Path,
    agent_a: str,
    agent_b: str,
) -> dict[str, Any]:
    events = build_timeline(input_path)

    ev_a = [e for e in events if e.get("agent_id") == agent_a]
    ev_b = [e for e in events if e.get("agent_id") == agent_b]

    types_a = Counter(e.get("event_type") or e.get("type", "unknown") for e in ev_a)
    types_b = Counter(e.get("event_type") or e.get("type", "unknown") for e in ev_b)

    all_types = sorted(set(types_a.keys()) | set(types_b.keys()))
    type_deltas: list[dict[str, Any]] = []
    for t in all_types:
        ca, cb = types_a.get(t, 0), types_b.get(t, 0)
        type_deltas.append({
            "type": t,
            agent_a: ca,
            agent_b: cb,
            "delta": cb - ca,
        })

    sources_a = Counter(e.get("source", "unknown") for e in ev_a)
    sources_b = Counter(e.get("source", "unknown") for e in ev_b)

    targets_a = Counter(
        e.get("target_agent") or e.get("dst_agent", "")
        for e in ev_a if e.get("target_agent") or e.get("dst_agent")
    )
    targets_b = Counter(
        e.get("target_agent") or e.get("dst_agent", "")
        for e in ev_b if e.get("target_agent") or e.get("dst_agent")
    )

    tools_a = Counter(e.get("tool_name", "") for e in ev_a if e.get("tool_name"))
    tools_b = Counter(e.get("tool_name", "") for e in ev_b if e.get("tool_name"))

    only_a_types = sorted(set(types_a) - set(types_b))
    only_b_types = sorted(set(types_b) - set(types_a))

    return {
        "agent_a": agent_a,
        "agent_b": agent_b,
        "events_a": len(ev_a),
        "events_b": len(ev_b),
        "type_deltas": type_deltas,
        "only_a_types": only_a_types,
        "only_b_types": only_b_types,
        "sources_a": dict(sources_a),
        "sources_b": dict(sources_b),
        "top_targets_a": dict(targets_a.most_common(5)),
        "top_targets_b": dict(targets_b.most_common(5)),
        "top_tools_a": dict(tools_a.most_common(5)),
        "top_tools_b": dict(tools_b.most_common(5)),
    }


def format_diff_agents_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    a, b = result["agent_a"], result["agent_b"]
    lines.append(f"Behavioral Delta: {a} vs {b}\n")
    lines.append(f"  Events: {a}={result['events_a']}, {b}={result['events_b']}")
    lines.append("")

    if result["type_deltas"]:
        lines.append("  Event type distribution:")
        for td in result["type_deltas"]:
            delta = td["delta"]
            sign = "+" if delta > 0 else ""
            lines.append(f"    {td['type']:<25} {td[a]:>5}  {td[b]:>5}  ({sign}{delta})")

    if result["only_a_types"]:
        lines.append(f"\n  Types only in {a}: {', '.join(result['only_a_types'])}")
    if result["only_b_types"]:
        lines.append(f"  Types only in {b}: {', '.join(result['only_b_types'])}")

    if result["top_tools_a"] or result["top_tools_b"]:
        lines.append(f"\n  Top tools ({a}): {', '.join(f'{k}({v})' for k, v in result['top_tools_a'].items())}")
        lines.append(f"  Top tools ({b}): {', '.join(f'{k}({v})' for k, v in result['top_tools_b'].items())}")

    lines.append("")
    return "\n".join(lines)
