"""Deep single-event analysis with surrounding context."""

from __future__ import annotations

import json
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


def list_events(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        raise FileNotFoundError(f"{path} is not a directory")
    events: list[dict[str, Any]] = []
    file_count = 0
    for f in sorted(path.glob("*.jsonl")):
        file_count += 1
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    index: list[dict[str, Any]] = []
    for ev in events:
        entry: dict[str, Any] = {}
        for key in ("event_id", "id", "message_id"):
            if key in ev:
                entry["event_id"] = ev[key]
                break
        entry["agent_id"] = ev.get("agent_id", "")
        entry["type"] = ev.get("event_type") or ev.get("type", "")
        entry["timestamp"] = ev.get("timestamp", "")
        index.append(entry)
    return {
        "total_events": len(events),
        "files": file_count,
        "index": index,
    }


def _nested_depth(obj: object, current: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return current + 1
        return max(_nested_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current + 1
        return max(_nested_depth(v, current + 1) for v in obj)
    return current


def inspect_event(
    path: Path,
    *,
    index: int | None = None,
    event_id: str | None = None,
    context: int = 3,
) -> dict[str, Any]:
    events = load_events(path)
    if not events:
        raise ValueError("no events found")

    target_idx: int | None = None
    if index is not None:
        if index < 0 or index >= len(events):
            raise ValueError(f"index {index} out of range (0-{len(events) - 1})")
        target_idx = index
    elif event_id is not None:
        for i, ev in enumerate(events):
            eid = ev.get("event_id") or ev.get("id") or ev.get("message_id")
            if eid == event_id:
                target_idx = i
                break
        if target_idx is None:
            raise ValueError(f"event_id {event_id!r} not found")
    else:
        raise ValueError("either --index or --event-id is required")

    target = events[target_idx]
    start = max(0, target_idx - context)
    end = min(len(events), target_idx + context + 1)

    before = events[start:target_idx]
    after = events[target_idx + 1 : end]

    time_deltas: list[dict[str, Any]] = []
    window = events[start:end]
    for i in range(1, len(window)):
        ts_prev = window[i - 1].get("timestamp", "")
        ts_curr = window[i].get("timestamp", "")
        time_deltas.append({"from_index": start + i - 1, "to_index": start + i, "from_ts": ts_prev, "to_ts": ts_curr})

    return {
        "index": target_idx,
        "total_events": len(events),
        "event": target,
        "context_before": before,
        "context_after": after,
        "time_deltas": time_deltas,
        "metadata": {
            "agent_id": target.get("agent_id", ""),
            "event_type": target.get("event_type") or target.get("type", ""),
            "timestamp": target.get("timestamp", ""),
        },
    }


def format_inspect_text(result: dict[str, Any]) -> str:
    if "index" in result and isinstance(result.get("index"), list):
        lines: list[str] = []
        lines.append(f"Events: {result['total_events']}\n")
        for i, entry in enumerate(result["index"]):
            parts = [f"  [{i}]"]
            if entry.get("event_id"):
                parts.append(entry["event_id"])
            if entry.get("type"):
                parts.append(f"type={entry['type']}")
            if entry.get("agent_id"):
                parts.append(f"agent={entry['agent_id']}")
            lines.append(" ".join(parts))
        lines.append("")
        return "\n".join(lines)

    lines: list[str] = []
    lines.append(f"Event #{result['index']} of {result['total_events']}")
    lines.append("")

    meta = result["metadata"]
    if meta["agent_id"]:
        lines.append(f"  Agent:      {meta['agent_id']}")
    if meta["event_type"]:
        lines.append(f"  Type:       {meta['event_type']}")
    if meta["timestamp"]:
        lines.append(f"  Timestamp:  {meta['timestamp']}")
    lines.append("")

    lines.append("  Event data:")
    for k, v in result["event"].items():
        lines.append(f"    {k}: {v}")
    lines.append("")

    if result["context_before"]:
        lines.append(f"  Context before ({len(result['context_before'])} events):")
        for ev in result["context_before"]:
            ts = ev.get("timestamp", "?")
            etype = ev.get("event_type") or ev.get("type", "?")
            agent = ev.get("agent_id", "?")
            lines.append(f"    [{ts}] {agent} -> {etype}")

    if result["context_after"]:
        lines.append(f"  Context after ({len(result['context_after'])} events):")
        for ev in result["context_after"]:
            ts = ev.get("timestamp", "?")
            etype = ev.get("event_type") or ev.get("type", "?")
            agent = ev.get("agent_id", "?")
            lines.append(f"    [{ts}] {agent} -> {etype}")

    if result["time_deltas"]:
        lines.append("")
        lines.append("  Time deltas:")
        for td in result["time_deltas"]:
            lines.append(f"    #{td['from_index']} -> #{td['to_index']}: {td['from_ts']} -> {td['to_ts']}")

    lines.append("")
    return "\n".join(lines)
