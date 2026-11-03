"""Cross-source event correlation for evidence datasets."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def _parse_ts(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, returning None on failure."""
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _read_events(path: Path, source: str, id_field: str) -> list[dict]:
    """Read a JSONL file and tag each row with its source and parsed timestamp."""
    if not path.exists():
        return []
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            agent_id = row.get("agent_id", "")
            if not agent_id:
                continue
            events.append({
                "source": source,
                "id": row.get(id_field, ""),
                "agent_id": agent_id,
                "timestamp": row.get("timestamp", ""),
                "_dt": _parse_ts(row.get("timestamp", "")),
            })
    return events


def correlate_events(input_dir: Path, time_window_seconds: int = 5) -> dict:
    """Correlate events across evidence sources by agent_id and time proximity.

    Groups events from messages, transcripts, and control_plane that share an
    agent_id and whose timestamps fall within *time_window_seconds* of each
    other.  Returns a summary with correlation groups, unmatched counts, and
    overall coverage.
    """
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    messages = _read_events(input_dir / "messages.jsonl", "messages", "event_id")
    transcripts = _read_events(input_dir / "transcripts.jsonl", "transcripts", "call_id")
    control = _read_events(input_dir / "control_plane.jsonl", "control_plane", "event_id")

    all_events = messages + transcripts + control
    total = len(all_events)
    if total == 0:
        return {
            "correlations": [],
            "unmatched_messages": 0,
            "unmatched_transcripts": 0,
            "unmatched_control_plane": 0,
            "coverage": 0.0,
        }

    by_agent: dict[str, list[dict]] = defaultdict(list)
    for ev in all_events:
        by_agent[ev["agent_id"]].append(ev)

    correlations: list[dict] = []
    matched_ids: set[int] = set()

    for agent_id, agent_events in sorted(by_agent.items()):
        timed = [e for e in agent_events if e["_dt"] is not None]
        untimed = [e for e in agent_events if e["_dt"] is None]

        timed.sort(key=lambda e: e["_dt"])  # type: ignore[arg-type]

        groups: list[list[dict]] = []
        for ev in timed:
            placed = False
            for g in groups:
                ref = g[0]["_dt"]
                diff = abs((ev["_dt"] - ref).total_seconds())  # type: ignore[union-attr]
                if diff <= time_window_seconds:
                    g.append(ev)
                    placed = True
                    break
            if not placed:
                groups.append([ev])

        # Untimed events go into their own single-event groups
        for ev in untimed:
            groups.append([ev])

        for g in groups:
            sources = {e["source"] for e in g}
            if len(sources) < 2 and len(g) < 2:
                continue
            timestamps = [e["_dt"] for e in g if e["_dt"] is not None]
            if len(timestamps) >= 2:
                span = (max(timestamps) - min(timestamps)).total_seconds()
            else:
                span = 0.0

            for e in g:
                matched_ids.add(id(e))

            correlations.append({
                "agent_id": agent_id,
                "events": [
                    {"source": e["source"], "id": e["id"], "timestamp": e["timestamp"]}
                    for e in g
                ],
                "sources": sorted(sources),
                "time_span_seconds": round(span, 3),
            })

    matched_count = len(matched_ids)
    unmatched_msg = sum(1 for e in messages if id(e) not in matched_ids)
    unmatched_tx = sum(1 for e in transcripts if id(e) not in matched_ids)
    unmatched_cp = sum(1 for e in control if id(e) not in matched_ids)

    coverage = matched_count / total if total > 0 else 0.0

    return {
        "correlations": correlations,
        "total_events": total,
        "matched_events": matched_count,
        "unmatched_messages": unmatched_msg,
        "unmatched_transcripts": unmatched_tx,
        "unmatched_control_plane": unmatched_cp,
        "coverage": round(coverage, 4),
    }


def format_correlate_text(result: dict) -> str:
    """Human-readable correlation summary."""
    lines = [
        f"Event correlation ({result.get('total_events', 0)} events)",
        f"  Matched:    {result.get('matched_events', 0)}",
        f"  Coverage:   {result['coverage']:.1%}",
        f"  Unmatched:  messages={result['unmatched_messages']}, "
        f"transcripts={result['unmatched_transcripts']}, "
        f"control_plane={result['unmatched_control_plane']}",
        f"  Groups:     {len(result['correlations'])}",
        "",
    ]
    for i, c in enumerate(result["correlations"], 1):
        src_str = ", ".join(c["sources"])
        lines.append(
            f"  [{i}] agent={c['agent_id']}  sources=[{src_str}]  "
            f"events={len(c['events'])}  span={c['time_span_seconds']}s"
        )
    return "\n".join(lines) + "\n"
