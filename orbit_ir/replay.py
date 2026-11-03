"""Chronological event replay with behavioral annotations."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def _parse_ts(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def replay_events(
    evidence_dir: Path,
    speed: float = 1.0,
    annotate: bool = True,
) -> list[dict]:
    """Load all evidence, merge chronologically, and annotate each event.

    Annotations flag: first appearance of an agent, tool claim mismatches,
    agents with unusually many communication peers, and large time gaps.
    """
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    events: list[dict] = []
    for row in _load_jsonl(evidence_dir / "messages.jsonl"):
        events.append({**row, "source": "messages"})
    for row in _load_jsonl(evidence_dir / "transcripts.jsonl"):
        events.append({**row, "source": "transcripts"})
    for row in _load_jsonl(evidence_dir / "control_plane.jsonl"):
        events.append({**row, "source": "control_plane"})

    events.sort(key=lambda e: _parse_ts(e.get("timestamp", "1970-01-01T00:00:00Z")))

    if not annotate:
        for e in events:
            e["annotations"] = []
        return events

    _annotate_events(events)
    return events


def _annotate_events(events: list[dict]) -> None:
    """Add annotations in-place to each event."""
    seen_agents: set[str] = set()
    peer_counts: dict[str, set[str]] = defaultdict(set)
    prev_dt: datetime | None = None

    # Pre-scan for peer counts to detect unusually connected agents.
    for e in events:
        if e.get("source") == "messages":
            agent = e.get("agent_id", "")
            recipient = e.get("recipient_agent_id")
            if agent and recipient:
                peer_counts[agent].add(recipient)
                peer_counts[recipient].add(agent)

    # Compute threshold: an agent with peers > mean + 2*stdev is "high-contact".
    if peer_counts:
        counts = [len(v) for v in peer_counts.values()]
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts) if len(counts) > 1 else 0
        stdev = variance ** 0.5
        high_contact_threshold = mean + 2 * stdev
    else:
        high_contact_threshold = float("inf")

    for e in events:
        annotations: list[str] = []
        agent = e.get("agent_id", "")

        # First appearance.
        if agent and agent not in seen_agents:
            annotations.append(f"first_seen:{agent}")
            seen_agents.add(agent)

        # Tool mismatch (transcripts have claimed vs actual).
        if e.get("source") == "transcripts":
            claimed = e.get("claimed_tool")
            actual = e.get("actual_tool")
            if claimed and actual and claimed != actual:
                annotations.append(f"tool_mismatch:{claimed}->{actual}")

        # High-contact agent.
        if agent and len(peer_counts.get(agent, set())) > high_contact_threshold:
            annotations.append(f"high_contact:{len(peer_counts[agent])}_peers")

        # Time gap from previous event.
        ts_str = e.get("timestamp")
        if ts_str:
            try:
                dt = _parse_ts(ts_str)
                if prev_dt is not None:
                    gap = (dt - prev_dt).total_seconds()
                    if gap > 60:
                        annotations.append(f"time_gap:{gap:.0f}s")
                prev_dt = dt
            except (ValueError, TypeError):
                pass

        e["annotations"] = annotations


def format_replay_text(events: list[dict], show_annotations: bool = True) -> str:
    """Format replay events as a human-readable timeline."""
    lines: list[str] = []
    for i, e in enumerate(events, 1):
        ts = e.get("timestamp", "?")
        src = e.get("source", "?")
        agent = e.get("agent_id", "?")
        detail = _event_detail(e)
        line = f"[{i:>4}] {ts}  [{src:14s}]  {agent:20s}  {detail}"

        if show_annotations and e.get("annotations"):
            ann_str = " | ".join(e["annotations"])
            line += f"  ** {ann_str}"

        lines.append(line)
    return "\n".join(lines) + "\n" if lines else ""


def _event_detail(e: dict) -> str:
    src = e.get("source", "")
    if src == "messages":
        recipient = e.get("recipient_agent_id", "")
        return f"msg to={recipient}" if recipient else "msg (broadcast)"
    if src == "transcripts":
        claimed = e.get("claimed_tool", "?")
        actual = e.get("actual_tool", "?")
        if claimed != actual:
            return f"tool claimed={claimed} actual={actual}"
        return f"tool={claimed}"
    if src == "control_plane":
        tool = e.get("tool", e.get("actual_tool", "?"))
        return f"control tool={tool}"
    return ""
