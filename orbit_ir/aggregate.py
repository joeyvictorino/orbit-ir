"""Multi-directory evidence aggregation."""

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


def _event_key(event: dict[str, Any]) -> str | None:
    return event.get("event_id") or event.get("id")


def aggregate_events(
    paths: list[Path],
    *,
    strategy: str = "union",
    deduplicate: bool = True,
) -> dict[str, Any]:
    source_stats: list[dict[str, Any]] = []
    all_events: list[tuple[int, dict[str, Any]]] = []

    for i, p in enumerate(paths):
        events = load_events(p)
        source_stats.append({
            "source": str(p),
            "event_count": len(events),
        })
        for ev in events:
            all_events.append((i, ev))

    num_sources = len(paths)

    if strategy == "intersect":
        key_sources: dict[str, set[int]] = defaultdict(set)
        key_events: dict[str, dict[str, Any]] = {}
        no_key: list[dict[str, Any]] = []
        for src_idx, ev in all_events:
            k = _event_key(ev)
            if k is None:
                no_key.append(ev)
                continue
            key_sources[k].add(src_idx)
            if k not in key_events:
                key_events[k] = ev
        merged = [
            key_events[k]
            for k in key_sources
            if len(key_sources[k]) == num_sources
        ]
    elif strategy == "unique":
        key_sources: dict[str, set[int]] = defaultdict(set)
        key_events: dict[str, dict[str, Any]] = {}
        for src_idx, ev in all_events:
            k = _event_key(ev)
            if k is None:
                continue
            key_sources[k].add(src_idx)
            if k not in key_events:
                key_events[k] = ev
        merged = [
            key_events[k]
            for k in key_sources
            if len(key_sources[k]) == 1
        ]
    else:
        merged_map: dict[str, dict[str, Any]] = {}
        no_key_events: list[dict[str, Any]] = []
        for _, ev in all_events:
            k = _event_key(ev)
            if k is None or not deduplicate:
                no_key_events.append(ev)
                continue
            if k not in merged_map:
                merged_map[k] = ev
        merged = list(merged_map.values()) + no_key_events

    return {
        "strategy": strategy,
        "sources": source_stats,
        "total_input": len(all_events),
        "total_output": len(merged),
        "deduplicated": deduplicate and strategy == "union",
        "events": merged,
    }


def format_aggregate_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Aggregate: strategy={result['strategy']}")
    lines.append(f"Sources: {len(result['sources'])}")
    for s in result["sources"]:
        lines.append(f"  - {s['source']}: {s['event_count']} events")
    lines.append(f"Total input events: {result['total_input']}")
    lines.append(f"Output events: {result['total_output']}")
    if result.get("deduplicated"):
        removed = result["total_input"] - result["total_output"]
        lines.append(f"Duplicates removed: {removed}")
    lines.append("")
    return "\n".join(lines)
