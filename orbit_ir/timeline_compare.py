"""Compare two timeline JSONL exports to find added, removed, and changed events."""

from __future__ import annotations

import json
from pathlib import Path


def _event_key(event: dict) -> str:
    """Stable key for matching events across timelines."""
    eid = event.get("event_id") or event.get("id") or event.get("message_id")
    if eid:
        return str(eid)
    ts = event.get("timestamp", "")
    agent = event.get("agent_id", "")
    source = event.get("source", "")
    return f"{ts}|{agent}|{source}"


def _diff_fields(a: dict, b: dict) -> dict[str, tuple]:
    """Return {field: (old, new)} for fields that differ."""
    all_keys = set(a.keys()) | set(b.keys())
    changes: dict[str, tuple] = {}
    for k in all_keys:
        va = a.get(k)
        vb = b.get(k)
        if va != vb:
            changes[k] = (va, vb)
    return changes


def compare_timelines(events_a: list[dict], events_b: list[dict]) -> dict:
    """Compare two lists of timeline events.

    Returns a dict with added, removed, changed events and summary stats.
    """
    map_a: dict[str, dict] = {}
    for e in events_a:
        key = _event_key(e)
        map_a[key] = e

    map_b: dict[str, dict] = {}
    for e in events_b:
        key = _event_key(e)
        map_b[key] = e

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    added_keys = keys_b - keys_a
    removed_keys = keys_a - keys_b
    common_keys = keys_a & keys_b

    added = [map_b[k] for k in sorted(added_keys)]
    removed = [map_a[k] for k in sorted(removed_keys)]

    changed = []
    unchanged_count = 0
    for k in sorted(common_keys):
        diffs = _diff_fields(map_a[k], map_b[k])
        if diffs:
            changed.append({
                "key": k,
                "event_a": map_a[k],
                "event_b": map_b[k],
                "changed_fields": {f: {"old": v[0], "new": v[1]} for f, v in diffs.items()},
            })
        else:
            unchanged_count += 1

    agents_a = {e.get("agent_id") for e in events_a if e.get("agent_id")}
    agents_b = {e.get("agent_id") for e in events_b if e.get("agent_id")}

    timestamps_a = sorted(e.get("timestamp", "") for e in events_a if e.get("timestamp"))
    timestamps_b = sorted(e.get("timestamp", "") for e in events_b if e.get("timestamp"))

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "unchanged_count": unchanged_count,
            "total_a": len(events_a),
            "total_b": len(events_b),
        },
        "agent_diff": {
            "added": sorted(agents_b - agents_a),
            "removed": sorted(agents_a - agents_b),
            "common": sorted(agents_a & agents_b),
        },
        "time_range_a": {
            "start": timestamps_a[0] if timestamps_a else None,
            "end": timestamps_a[-1] if timestamps_a else None,
        },
        "time_range_b": {
            "start": timestamps_b[0] if timestamps_b else None,
            "end": timestamps_b[-1] if timestamps_b else None,
        },
    }


def format_compare_text(result: dict) -> str:
    """Render timeline comparison as human-readable text."""
    s = result["summary"]
    lines = [
        "Timeline Comparison",
        "=" * 40,
        f"Timeline A: {s['total_a']} events",
        f"Timeline B: {s['total_b']} events",
        "",
        f"Added:     {s['added_count']}",
        f"Removed:   {s['removed_count']}",
        f"Changed:   {s['changed_count']}",
        f"Unchanged: {s['unchanged_count']}",
        "",
    ]

    ad = result["agent_diff"]
    if ad["added"]:
        lines.append(f"New agents: {', '.join(ad['added'])}")
    if ad["removed"]:
        lines.append(f"Removed agents: {', '.join(ad['removed'])}")
    if ad["added"] or ad["removed"]:
        lines.append("")

    if result["added"][:5]:
        lines.append("Sample added events:")
        for e in result["added"][:5]:
            ts = e.get("timestamp", "?")
            agent = e.get("agent_id", "?")
            lines.append(f"  [{ts}] {agent}")
        lines.append("")

    if result["removed"][:5]:
        lines.append("Sample removed events:")
        for e in result["removed"][:5]:
            ts = e.get("timestamp", "?")
            agent = e.get("agent_id", "?")
            lines.append(f"  [{ts}] {agent}")
        lines.append("")

    if result["changed"][:5]:
        lines.append("Sample changed events:")
        for c in result["changed"][:5]:
            lines.append(f"  Key: {c['key']}")
            for field, vals in c["changed_fields"].items():
                lines.append(f"    {field}: {vals['old']} -> {vals['new']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def load_and_compare(path_a: Path, path_b: Path) -> dict:
    """Load two JSONL timeline files and compare them."""
    def load_jsonl(p: Path) -> list[dict]:
        events: list[dict] = []
        with p.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    return compare_timelines(load_jsonl(path_a), load_jsonl(path_b))
