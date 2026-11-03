"""Event frequency analysis across agents and event types."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path


def build_frequency(events: list[dict]) -> dict:
    """Compute event frequency distributions.

    Returns per-agent counts, per-type counts, hourly distribution,
    and basic statistics.
    """
    by_agent: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_hour: dict[int, int] = defaultdict(int)

    for e in events:
        agent = e.get("agent_id", "unknown")
        by_agent[agent] += 1

        etype = e.get("event_type") or e.get("type") or e.get("detection_type", "unknown")
        by_type[etype] += 1

        ts = e.get("timestamp", "")
        if len(ts) >= 13 and ts[10] == "T":
            try:
                hour = int(ts[11:13])
                by_hour[hour] += 1
            except ValueError:
                pass

    total = len(events)
    agent_counts = sorted(by_agent.items(), key=lambda x: -x[1])
    type_counts = sorted(by_type.items(), key=lambda x: -x[1])
    hour_dist = {h: by_hour.get(h, 0) for h in range(24)}

    values = list(by_agent.values())
    stats = _compute_stats(values)

    return {
        "total_events": total,
        "unique_agents": len(by_agent),
        "unique_types": len(by_type),
        "by_agent": agent_counts,
        "by_type": type_counts,
        "hourly_distribution": hour_dist,
        "agent_stats": stats,
    }


def _compute_stats(values: list[int]) -> dict:
    if not values:
        return {"mean": 0.0, "stddev": 0.0, "min": 0, "max": 0, "median": 0.0}
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    stddev = math.sqrt(variance)
    s = sorted(values)
    if n % 2 == 0:
        median = (s[n // 2 - 1] + s[n // 2]) / 2
    else:
        median = float(s[n // 2])
    return {
        "mean": round(mean, 2),
        "stddev": round(stddev, 2),
        "min": s[0],
        "max": s[-1],
        "median": median,
    }


def format_frequency_text(result: dict) -> str:
    lines = [
        "Event Frequency Analysis",
        "=" * 40,
        f"Total events:  {result['total_events']}",
        f"Unique agents: {result['unique_agents']}",
        f"Unique types:  {result['unique_types']}",
        "",
    ]

    stats = result["agent_stats"]
    lines.append(f"Agent event stats: mean={stats['mean']}, stddev={stats['stddev']}, "
                 f"min={stats['min']}, max={stats['max']}, median={stats['median']}")
    lines.append("")

    lines.append("Top agents by event count:")
    for agent, count in result["by_agent"][:15]:
        lines.append(f"  {agent:30s}  {count}")
    lines.append("")

    lines.append("Top event types:")
    for etype, count in result["by_type"][:15]:
        lines.append(f"  {etype:30s}  {count}")
    lines.append("")

    lines.append("Hourly distribution:")
    max_count = max(result["hourly_distribution"].values()) if result["hourly_distribution"] else 1
    for hour in range(24):
        count = result["hourly_distribution"].get(hour, 0)
        bar_len = int(40 * count / max_count) if max_count > 0 else 0
        lines.append(f"  {hour:02d}:00  {'#' * bar_len} ({count})")
    lines.append("")

    return "\n".join(lines) + "\n"


def load_and_build(input_path: Path) -> dict:
    events: list[dict] = []
    if input_path.is_dir():
        for f in sorted(input_path.glob("*.jsonl")):
            with f.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
    else:
        with input_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return build_frequency(events)
