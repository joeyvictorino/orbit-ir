"""Timeline differential — compares two incident timelines and highlights differences."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TimelineDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    modified: list[tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=list)
    timing_shifts: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    elif path.is_dir():
        for f in sorted(path.iterdir()):
            if f.suffix in (".json", ".jsonl"):
                events.extend(_load_events(f))
    return events


def _event_key(event: dict, match_keys: list[str] | None = None) -> str:
    if match_keys:
        parts = [str(event.get(k, "")) for k in match_keys]
        return "|".join(parts)
    eid = event.get("event_id", event.get("id", ""))
    if eid:
        return str(eid)
    ts = event.get("timestamp", "")
    action = event.get("action", event.get("event_type", ""))
    agent = event.get("agent_id", event.get("agent", ""))
    return f"{ts}|{action}|{agent}"


def _parse_timestamp(ts: str) -> float | None:
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", ts)
    if not m:
        return None
    import calendar
    import time
    try:
        t = time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
        return float(calendar.timegm(t))
    except (ValueError, OverflowError):
        try:
            t = time.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            return float(calendar.timegm(t))
        except (ValueError, OverflowError):
            return None


def _fields_differ(a: dict, b: dict) -> dict[str, tuple]:
    diffs: dict[str, tuple] = {}
    all_keys = set(a.keys()) | set(b.keys())
    skip = {"timestamp", "event_id", "id"}
    for k in all_keys - skip:
        va = a.get(k)
        vb = b.get(k)
        if va != vb:
            diffs[k] = (va, vb)
    return diffs


def detect_timing_shifts(
    baseline: list[dict],
    compare: list[dict],
    threshold_seconds: float = 60.0,
    match_keys: list[str] | None = None,
) -> list[dict]:
    shifts: list[dict] = []
    compare_map: dict[str, dict] = {}
    for ev in compare:
        key = _event_key(ev, match_keys)
        compare_map[key] = ev

    for bev in baseline:
        key = _event_key(bev, match_keys)
        cev = compare_map.get(key)
        if cev is None:
            continue
        bts = _parse_timestamp(bev.get("timestamp", ""))
        cts = _parse_timestamp(cev.get("timestamp", ""))
        if bts is not None and cts is not None:
            delta = abs(cts - bts)
            if delta >= threshold_seconds:
                shifts.append({
                    "event_key": key,
                    "baseline_timestamp": bev.get("timestamp", ""),
                    "compare_timestamp": cev.get("timestamp", ""),
                    "shift_seconds": round(delta, 1),
                    "direction": "later" if cts > bts else "earlier",
                })
    return shifts


def diff_timelines(
    baseline: list[dict],
    compare: list[dict],
    match_keys: list[str] | None = None,
    threshold_seconds: float = 60.0,
) -> TimelineDiff:
    result = TimelineDiff()

    base_map: dict[str, dict] = {}
    for ev in baseline:
        key = _event_key(ev, match_keys)
        base_map[key] = ev

    comp_map: dict[str, dict] = {}
    for ev in compare:
        key = _event_key(ev, match_keys)
        comp_map[key] = ev

    for key, cev in comp_map.items():
        if key not in base_map:
            result.added.append(cev)

    for key, bev in base_map.items():
        if key not in comp_map:
            result.removed.append(bev)

    for key in base_map:
        if key in comp_map:
            diffs = _fields_differ(base_map[key], comp_map[key])
            if diffs:
                result.modified.append((base_map[key], comp_map[key]))

    result.timing_shifts = detect_timing_shifts(
        baseline, compare, threshold_seconds=threshold_seconds, match_keys=match_keys
    )

    result.summary = summarize_diff(result)
    return result


def summarize_diff(diff: TimelineDiff) -> dict:
    return {
        "added": len(diff.added),
        "removed": len(diff.removed),
        "modified": len(diff.modified),
        "timing_shifts": len(diff.timing_shifts),
        "total_changes": len(diff.added) + len(diff.removed) + len(diff.modified),
    }


def format_diff_text(diff: TimelineDiff) -> str:
    lines: list[str] = []
    lines.append("Timeline Differential")
    lines.append("=" * 60)
    lines.append("")

    s = diff.summary or summarize_diff(diff)
    lines.append(f"  Added events:    {s['added']}")
    lines.append(f"  Removed events:  {s['removed']}")
    lines.append(f"  Modified events: {s['modified']}")
    lines.append(f"  Timing shifts:   {s['timing_shifts']}")
    lines.append(f"  Total changes:   {s['total_changes']}")
    lines.append("")

    if diff.added:
        lines.append("  Added Events (+):")
        for ev in diff.added[:20]:
            ts = ev.get("timestamp", "?")
            action = ev.get("action", ev.get("event_type", "?"))
            agent = ev.get("agent_id", ev.get("agent", "?"))
            lines.append(f"    + {ts}  {agent:<20} {action}")
        if len(diff.added) > 20:
            lines.append(f"    ... and {len(diff.added) - 20} more")
        lines.append("")

    if diff.removed:
        lines.append("  Removed Events (-):")
        for ev in diff.removed[:20]:
            ts = ev.get("timestamp", "?")
            action = ev.get("action", ev.get("event_type", "?"))
            agent = ev.get("agent_id", ev.get("agent", "?"))
            lines.append(f"    - {ts}  {agent:<20} {action}")
        if len(diff.removed) > 20:
            lines.append(f"    ... and {len(diff.removed) - 20} more")
        lines.append("")

    if diff.modified:
        lines.append("  Modified Events (~):")
        for old, new in diff.modified[:10]:
            eid = old.get("event_id", old.get("id", "?"))
            diffs = _fields_differ(old, new)
            lines.append(f"    ~ {eid}:")
            for field_name, (va, vb) in list(diffs.items())[:5]:
                lines.append(f"        {field_name}: {va!r} -> {vb!r}")
        if len(diff.modified) > 10:
            lines.append(f"    ... and {len(diff.modified) - 10} more")
        lines.append("")

    if diff.timing_shifts:
        lines.append("  Timing Shifts:")
        for ts in diff.timing_shifts[:10]:
            lines.append(
                f"    {ts['event_key']}: {ts['shift_seconds']}s {ts['direction']} "
                f"({ts['baseline_timestamp']} -> {ts['compare_timestamp']})"
            )
        if len(diff.timing_shifts) > 10:
            lines.append(f"    ... and {len(diff.timing_shifts) - 10} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def load_and_diff(
    baseline_path: Path,
    compare_path: Path,
    match_keys: list[str] | None = None,
    threshold_seconds: float = 60.0,
) -> TimelineDiff:
    baseline = _load_events(baseline_path)
    compare = _load_events(compare_path)
    return diff_timelines(
        baseline, compare, match_keys=match_keys, threshold_seconds=threshold_seconds
    )
