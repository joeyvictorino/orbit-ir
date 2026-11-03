"""Evidence replay simulator — replays events chronologically and scores fidelity."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class ReplayEvent:
    timestamp: str
    agent: str
    action: str
    source_file: str
    in_order: bool


@dataclass
class ReplayAnomaly:
    kind: str  # gap | out_of_order | duplicate | missing_timestamp
    description: str
    index: int
    severity: str = "medium"


@dataclass
class ReplayReport:
    events: List[ReplayEvent]
    total: int = 0
    in_order_count: int = 0
    gap_count: int = 0
    fidelity_score: float = 0.0
    anomalies: List[ReplayAnomaly] = field(default_factory=list)


def _load_events(evidence_dir: Path):
    """Load events from JSON files in evidence directory."""
    events = []
    edir = Path(evidence_dir)
    if not edir.is_dir():
        return events
    for fpath in sorted(edir.iterdir()):
        if not fpath.suffix == ".json":
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    events.append((item, fpath.name))
        elif isinstance(data, dict):
            if "events" in data and isinstance(data["events"], list):
                for item in data["events"]:
                    if isinstance(item, dict):
                        events.append((item, fpath.name))
            else:
                events.append((data, fpath.name))
    return events


def analyze(evidence_dir: Path) -> ReplayReport:
    raw = _load_events(evidence_dir)
    if not raw:
        return ReplayReport(events=[], total=0, fidelity_score=1.0)

    replay_events: list[ReplayEvent] = []
    for item, source in raw:
        ts = item.get("timestamp", item.get("time", ""))
        agent = item.get("agent", item.get("agent_id", "unknown"))
        action = item.get("action", item.get("type", item.get("kind", "unknown")))
        replay_events.append(ReplayEvent(
            timestamp=str(ts),
            agent=str(agent),
            action=str(action),
            source_file=source,
            in_order=True,
        ))

    # Sort by timestamp for replay
    with_ts = [(e, e.timestamp) for e in replay_events]
    sorted_by_ts = sorted(with_ts, key=lambda x: x[1])

    anomalies: list[ReplayAnomaly] = []
    in_order_count = 0
    gap_count = 0
    missing_ts = 0

    for i, (event, ts) in enumerate(sorted_by_ts):
        if not ts:
            missing_ts += 1
            event.in_order = False
            anomalies.append(ReplayAnomaly(
                kind="missing_timestamp",
                description=f"Event {i} from {event.source_file} has no timestamp",
                index=i,
                severity="high",
            ))
            continue

        if i > 0:
            prev_ts = sorted_by_ts[i - 1][1]
            if ts < prev_ts:
                event.in_order = False
                anomalies.append(ReplayAnomaly(
                    kind="out_of_order",
                    description=f"Event {i} timestamp {ts} before previous {prev_ts}",
                    index=i,
                    severity="medium",
                ))
            else:
                in_order_count += 1
        else:
            in_order_count += 1

    # Detect gaps: check original order vs sorted order
    original_indices = {id(e): idx for idx, (e, _) in enumerate(with_ts)}
    for i, (event, _) in enumerate(sorted_by_ts):
        orig_idx = original_indices[id(event)]
        if abs(orig_idx - i) > len(replay_events) * 0.3:
            gap_count += 1

    # Detect duplicates
    seen = set()
    for i, (event, ts) in enumerate(sorted_by_ts):
        key = (ts, event.agent, event.action)
        if key in seen:
            anomalies.append(ReplayAnomaly(
                kind="duplicate",
                description=f"Duplicate event at index {i}: {event.agent}/{event.action}@{ts}",
                index=i,
                severity="low",
            ))
        seen.add(key)

    total = len(replay_events)
    fidelity = in_order_count / total if total > 0 else 1.0
    ordered_events = [e for e, _ in sorted_by_ts]

    return ReplayReport(
        events=ordered_events,
        total=total,
        in_order_count=in_order_count,
        gap_count=gap_count,
        fidelity_score=round(fidelity, 4),
        anomalies=anomalies,
    )


def format_text(report: ReplayReport) -> str:
    lines = [
        "Evidence Replay Analysis",
        "=" * 62,
        "",
    ]
    if report.total == 0:
        lines.append("  No events to replay.")
        return "\n".join(lines) + "\n"

    lines.append(f"  Total events:     {report.total}")
    lines.append(f"  In-order:         {report.in_order_count}")
    lines.append(f"  Gaps detected:    {report.gap_count}")
    lines.append(f"  Fidelity score:   {report.fidelity_score:.0%}")
    lines.append(f"  Anomalies:        {len(report.anomalies)}")
    lines.append("")

    if report.anomalies:
        lines.append("Anomalies")
        lines.append("-" * 62)
        for a in report.anomalies[:20]:
            lines.append(f"  [{a.severity}] {a.kind}: {a.description}")
        if len(report.anomalies) > 20:
            lines.append(f"  ... and {len(report.anomalies) - 20} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ReplayReport) -> str:
    d = asdict(report)
    d.pop("events", None)
    d["event_count"] = report.total
    return json.dumps(d, indent=2) + "\n"
