"""Statistical outlier detection for agent event patterns."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path


def detect_outliers(events: list[dict], z_threshold: float = 2.0) -> dict:
    """Detect statistically unusual event patterns using z-scores.

    Checks for:
    - Agents with unusually high/low event counts
    - Unusual event type frequencies
    - Burst periods (time windows with abnormal activity)
    """
    by_agent: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_window: dict[str, int] = defaultdict(int)

    for e in events:
        agent = e.get("agent_id", "unknown")
        by_agent[agent] += 1

        etype = e.get("event_type") or e.get("type") or e.get("detection_type", "unknown")
        by_type[etype] += 1

        ts = e.get("timestamp", "")
        if len(ts) >= 13 and ts[10] == "T":
            window = ts[:13]
            by_window[window] += 1

    agent_outliers = _find_outliers(dict(by_agent), z_threshold)
    type_outliers = _find_outliers(dict(by_type), z_threshold)
    burst_outliers = _find_outliers(dict(by_window), z_threshold)

    return {
        "z_threshold": z_threshold,
        "total_events": len(events),
        "agent_outliers": agent_outliers,
        "type_outliers": type_outliers,
        "burst_windows": burst_outliers,
        "summary": {
            "agents_checked": len(by_agent),
            "agent_outlier_count": len(agent_outliers),
            "types_checked": len(by_type),
            "type_outlier_count": len(type_outliers),
            "windows_checked": len(by_window),
            "burst_count": len(burst_outliers),
        },
    }


def _find_outliers(counts: dict[str, int], z_threshold: float) -> list[dict]:
    if not counts:
        return []
    values = list(counts.values())
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    stddev = math.sqrt(variance)
    if stddev == 0:
        return []

    outliers = []
    for key, count in sorted(counts.items(), key=lambda x: -abs(x[1] - mean)):
        z = (count - mean) / stddev
        if abs(z) >= z_threshold:
            outliers.append({
                "key": key,
                "count": count,
                "z_score": round(z, 3),
                "direction": "high" if z > 0 else "low",
                "mean": round(mean, 2),
                "stddev": round(stddev, 2),
            })
    return outliers


def format_outlier_text(result: dict) -> str:
    s = result["summary"]
    lines = [
        "Outlier Detection Report",
        "=" * 40,
        f"Z-score threshold: {result['z_threshold']}",
        f"Total events: {result['total_events']}",
        "",
        f"Agents:  {s['agents_checked']} checked, {s['agent_outlier_count']} outliers",
        f"Types:   {s['types_checked']} checked, {s['type_outlier_count']} outliers",
        f"Windows: {s['windows_checked']} checked, {s['burst_count']} bursts",
        "",
    ]

    if result["agent_outliers"]:
        lines.append("Agent outliers:")
        for o in result["agent_outliers"][:10]:
            lines.append(f"  {o['key']:30s}  count={o['count']:5d}  z={o['z_score']:+.3f}  ({o['direction']})")
        lines.append("")

    if result["type_outliers"]:
        lines.append("Event type outliers:")
        for o in result["type_outliers"][:10]:
            lines.append(f"  {o['key']:30s}  count={o['count']:5d}  z={o['z_score']:+.3f}  ({o['direction']})")
        lines.append("")

    if result["burst_windows"]:
        lines.append("Burst time windows:")
        for o in result["burst_windows"][:10]:
            lines.append(f"  {o['key']:20s}  count={o['count']:5d}  z={o['z_score']:+.3f}")
        lines.append("")

    if not result["agent_outliers"] and not result["type_outliers"] and not result["burst_windows"]:
        lines.append("No outliers detected at the given threshold.")
        lines.append("")

    return "\n".join(lines) + "\n"


def load_and_detect(input_path: Path, z_threshold: float = 2.0) -> dict:
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
    return detect_outliers(events, z_threshold)
