"""Behavioral baseline comparison for agent event streams."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def _load_events(path: Path) -> list[dict[str, Any]]:
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


def _build_profile(events: list[dict[str, Any]]) -> dict[str, Any]:
    types: Counter[str] = Counter()
    agents: Counter[str] = Counter()
    severities: Counter[str] = Counter()

    for ev in events:
        types[ev.get("type", "unknown")] += 1
        agent = ev.get("agent_id", "unknown")
        agents[agent] += 1
        sev = ev.get("severity", "")
        if sev:
            severities[sev.lower()] += 1

    total = len(events) or 1
    return {
        "event_count": len(events),
        "type_distribution": {k: round(v / total, 4) for k, v in types.items()},
        "agent_distribution": {k: round(v / total, 4) for k, v in agents.items()},
        "severity_distribution": {k: round(v / total, 4) for k, v in severities.items()},
        "unique_types": len(types),
        "unique_agents": len(agents),
    }


def create_baseline(input_path: Path) -> dict[str, Any]:
    events = _load_events(input_path)
    profile = _build_profile(events)
    return {"baseline": profile}


def compare_baseline(
    input_path: Path,
    baseline_path: Path,
    *,
    drift_threshold: float = 0.1,
) -> dict[str, Any]:
    events = _load_events(input_path)
    current = _build_profile(events)

    baseline_data = json.loads(baseline_path.read_text())
    baseline = baseline_data.get("baseline", baseline_data)

    deviations: list[dict[str, Any]] = []

    bl_types = baseline.get("type_distribution", {})
    cur_types = current.get("type_distribution", {})
    all_types = set(bl_types) | set(cur_types)
    for t in sorted(all_types):
        bl_val = bl_types.get(t, 0.0)
        cur_val = cur_types.get(t, 0.0)
        diff = abs(cur_val - bl_val)
        if diff >= drift_threshold:
            deviations.append({
                "dimension": "type",
                "key": t,
                "baseline_value": bl_val,
                "current_value": cur_val,
                "drift": round(diff, 4),
            })

    bl_sev = baseline.get("severity_distribution", {})
    cur_sev = current.get("severity_distribution", {})
    all_sev = set(bl_sev) | set(cur_sev)
    for s in sorted(all_sev):
        bl_val = bl_sev.get(s, 0.0)
        cur_val = cur_sev.get(s, 0.0)
        diff = abs(cur_val - bl_val)
        if diff >= drift_threshold:
            deviations.append({
                "dimension": "severity",
                "key": s,
                "baseline_value": bl_val,
                "current_value": cur_val,
                "drift": round(diff, 4),
            })

    new_types = set(cur_types) - set(bl_types)
    missing_types = set(bl_types) - set(cur_types)

    deviations.sort(key=lambda d: d["drift"], reverse=True)

    return {
        "total_events": len(events),
        "baseline_events": baseline.get("event_count", 0),
        "deviations": deviations,
        "deviation_count": len(deviations),
        "new_types": sorted(new_types),
        "missing_types": sorted(missing_types),
        "drift_threshold": drift_threshold,
        "current_profile": current,
    }


def format_baseline_text(result: dict[str, Any]) -> str:
    if "baseline" in result:
        bl = result["baseline"]
        lines = [
            f"Baseline Profile ({bl['event_count']} events)",
            "=" * 50,
            f"  Unique event types: {bl['unique_types']}",
            f"  Unique agents: {bl['unique_agents']}",
            "",
            "  Type distribution:",
        ]
        for t, pct in sorted(bl["type_distribution"].items(), key=lambda x: -x[1]):
            lines.append(f"    {t:20s}: {pct:.1%}")
        if bl["severity_distribution"]:
            lines.append("")
            lines.append("  Severity distribution:")
            for s, pct in sorted(bl["severity_distribution"].items(), key=lambda x: -x[1]):
                lines.append(f"    {s:12s}: {pct:.1%}")
        return "\n".join(lines)

    lines = [
        f"Baseline Comparison ({result['total_events']} current vs {result['baseline_events']} baseline events)",
        "=" * 50,
        "",
    ]

    devs = result.get("deviations", [])
    if devs:
        lines.append(f"Deviations (threshold >= {result['drift_threshold']}):")
        for d in devs:
            lines.append(
                f"  [{d['dimension']}] {d['key']}: "
                f"{d['baseline_value']:.1%} -> {d['current_value']:.1%} "
                f"(drift {d['drift']:.1%})"
            )
    else:
        lines.append("No significant deviations from baseline.")

    new = result.get("new_types", [])
    if new:
        lines.append(f"\nNew event types: {', '.join(new)}")
    missing = result.get("missing_types", [])
    if missing:
        lines.append(f"Missing event types: {', '.join(missing)}")

    return "\n".join(lines)
