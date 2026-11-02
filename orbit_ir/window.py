"""Sliding window analysis over time-ordered events."""

from __future__ import annotations

import json
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


def _get_timestamp(ev: dict[str, Any]) -> float:
    ts = ev.get("timestamp") or ev.get("ts") or ev.get("time", 0)
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return float(ts)
    except (ValueError, TypeError):
        return 0.0


def window_analysis(
    path: Path,
    *,
    window_size: int = 10,
    step: int | None = None,
    metric: str = "count",
) -> dict[str, Any]:
    events = load_events(path)
    events.sort(key=_get_timestamp)

    if step is None:
        step = max(1, window_size // 2)

    windows: list[dict[str, Any]] = []
    n = len(events)
    if n == 0:
        return {
            "total_events": 0,
            "window_size": window_size,
            "step": step,
            "metric": metric,
            "windows": [],
        }

    i = 0
    win_idx = 0
    while i < n:
        end = min(i + window_size, n)
        chunk = events[i:end]

        ts_start = _get_timestamp(chunk[0]) if chunk else 0
        ts_end = _get_timestamp(chunk[-1]) if chunk else 0

        if metric == "agents":
            agents = set()
            for ev in chunk:
                a = ev.get("agent_id")
                if a:
                    agents.add(a)
            value = len(agents)
        elif metric == "types":
            types = set()
            for ev in chunk:
                t = ev.get("event_type") or ev.get("type", "")
                if t:
                    types.add(t)
            value = len(types)
        elif metric == "errors":
            value = sum(
                1 for ev in chunk
                if (ev.get("event_type") or ev.get("type", "")) in ("error", "failure", "exception")
            )
        else:
            value = len(chunk)

        windows.append({
            "window": win_idx,
            "start_index": i,
            "end_index": end - 1,
            "ts_start": ts_start,
            "ts_end": ts_end,
            "event_count": len(chunk),
            "value": value,
        })
        win_idx += 1
        i += step

    return {
        "total_events": n,
        "window_size": window_size,
        "step": step,
        "metric": metric,
        "windows": windows,
    }


def format_window_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Sliding Window Analysis (metric={result['metric']})")
    lines.append(f"Total events: {result['total_events']}  Window: {result['window_size']}  Step: {result['step']}\n")

    if not result["windows"]:
        lines.append("  No windows.\n")
        return "\n".join(lines)

    header = f"{'Win':<6}{'Events':<8}{'Value':<8}{'Start':<12}{'End':<12}"
    lines.append(header)
    lines.append("-" * len(header))

    for w in result["windows"]:
        lines.append(
            f"{w['window']:<6}{w['event_count']:<8}{w['value']:<8}"
            f"{w['ts_start']:<12.1f}{w['ts_end']:<12.1f}"
        )

    lines.append("")
    return "\n".join(lines)
