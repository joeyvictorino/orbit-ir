"""Anomaly pattern detection in agent event streams."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
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


def _get_ts(ev: dict[str, Any]) -> float:
    ts = ev.get("timestamp") or ev.get("ts") or ev.get("time", 0)
    try:
        return float(ts)
    except (ValueError, TypeError):
        return 0.0


def detect_anomalies(
    path: Path,
    *,
    patterns: list[str] | None = None,
    threshold: float = 2.0,
) -> dict[str, Any]:
    events = load_events(path)
    detections: list[dict[str, Any]] = []

    if patterns is None:
        patterns = ["burst", "repeat", "escalation", "unusual_type"]

    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        aid = ev.get("agent_id")
        if aid:
            agent_events[aid].append(ev)

    if "burst" in patterns:
        detections.extend(_detect_burst(agent_events, threshold))

    if "repeat" in patterns:
        detections.extend(_detect_repeat(agent_events, threshold))

    if "escalation" in patterns:
        detections.extend(_detect_escalation(agent_events))

    if "unusual_type" in patterns:
        detections.extend(_detect_unusual_type(events, threshold))

    detections.sort(key=lambda d: d.get("severity_score", 0), reverse=True)

    return {
        "total_events": len(events),
        "patterns_checked": patterns,
        "detections": detections,
        "detection_count": len(detections),
    }


def _detect_burst(
    agent_events: dict[str, list[dict[str, Any]]],
    threshold: float,
) -> list[dict[str, Any]]:
    detections = []
    for aid, evs in agent_events.items():
        if len(evs) < 5:
            continue
        evs_sorted = sorted(evs, key=_get_ts)
        gaps = []
        for i in range(1, len(evs_sorted)):
            t1 = _get_ts(evs_sorted[i - 1])
            t2 = _get_ts(evs_sorted[i])
            if t1 > 0 and t2 > 0:
                gaps.append(t2 - t1)

        if not gaps:
            continue

        avg_gap = sum(gaps) / len(gaps)
        if avg_gap == 0:
            continue

        for i, g in enumerate(gaps):
            if g > 0 and avg_gap / g > threshold:
                detections.append({
                    "pattern": "burst",
                    "agent_id": aid,
                    "description": f"Rapid burst: gap {g:.2f} vs avg {avg_gap:.2f}",
                    "event_index": i,
                    "severity_score": round(avg_gap / g, 2),
                })
    return detections


def _detect_repeat(
    agent_events: dict[str, list[dict[str, Any]]],
    threshold: float,
) -> list[dict[str, Any]]:
    detections = []
    for aid, evs in agent_events.items():
        types = [ev.get("event_type") or ev.get("type", "") for ev in evs]
        for i in range(len(types) - 2):
            run_len = 1
            while i + run_len < len(types) and types[i + run_len] == types[i]:
                run_len += 1
            if run_len >= max(3, threshold):
                detections.append({
                    "pattern": "repeat",
                    "agent_id": aid,
                    "description": f"Repeated '{types[i]}' x{run_len} starting at index {i}",
                    "event_index": i,
                    "severity_score": round(run_len / 3.0, 2),
                })
    return detections


def _detect_escalation(
    agent_events: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    detections = []
    for aid, evs in agent_events.items():
        sevs = []
        for ev in evs:
            s = ev.get("severity", "").lower()
            if s in sev_order:
                sevs.append((sev_order[s], s))
        if len(sevs) < 2:
            continue
        escalations = 0
        for i in range(1, len(sevs)):
            if sevs[i][0] > sevs[i - 1][0]:
                escalations += 1
        if escalations >= 2:
            detections.append({
                "pattern": "escalation",
                "agent_id": aid,
                "description": f"Severity escalation pattern: {escalations} increases",
                "severity_score": round(escalations * 1.5, 2),
            })
    return detections


def _detect_unusual_type(
    events: list[dict[str, Any]],
    threshold: float,
) -> list[dict[str, Any]]:
    type_counts = Counter()
    for ev in events:
        t = ev.get("event_type") or ev.get("type", "")
        if t:
            type_counts[t] += 1

    if not type_counts:
        return []

    total = sum(type_counts.values())
    avg = total / len(type_counts)
    detections = []
    for t, c in type_counts.items():
        if c == 1 and avg > threshold:
            detections.append({
                "pattern": "unusual_type",
                "description": f"Rare event type '{t}' (1 of {total})",
                "severity_score": round(avg, 2),
            })
    return detections


def format_detect_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Anomaly Detection")
    lines.append(f"Total events: {result['total_events']}  Patterns: {', '.join(result['patterns_checked'])}")
    lines.append(f"Detections: {result['detection_count']}\n")

    if not result["detections"]:
        lines.append("  No anomalies detected.\n")
        return "\n".join(lines)

    for i, d in enumerate(result["detections"]):
        agent = d.get("agent_id", "global")
        lines.append(
            f"  [{i}] [{d['pattern']}] agent={agent}  "
            f"score={d['severity_score']}  {d['description']}"
        )

    lines.append("")
    return "\n".join(lines)
