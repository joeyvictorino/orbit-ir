"""Merge evidence files into a single chronological timeline."""

from __future__ import annotations

import json
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


def build_timeline(input_dir: Path) -> list[dict]:
    """Load all three evidence files and merge into a timestamp-sorted list.

    Each entry is ``{"timestamp", "source", "agent_id", ...original fields}``.
    """
    events: list[dict] = []

    for row in _load_jsonl(input_dir / "messages.jsonl"):
        events.append({**row, "source": "messages"})

    for row in _load_jsonl(input_dir / "transcripts.jsonl"):
        events.append({**row, "source": "transcripts"})

    for row in _load_jsonl(input_dir / "control_plane.jsonl"):
        events.append({**row, "source": "control_plane"})

    events.sort(key=lambda e: _parse_ts(e.get("timestamp", "1970-01-01T00:00:00Z")))
    return events


def format_text(events: list[dict]) -> str:
    """Render the timeline as a human-readable text table."""
    lines: list[str] = []
    for e in events:
        ts = e.get("timestamp", "?")
        src = e.get("source", "?")
        agent = e.get("agent_id", "?")
        detail = _detail(e)
        lines.append(f"{ts}  [{src:14s}]  {agent:20s}  {detail}")
    return "\n".join(lines) + "\n" if lines else ""


def _detail(e: dict) -> str:
    src = e.get("source", "")
    if src == "messages":
        mtype = e.get("message_type", "?")
        recipient = e.get("recipient_agent_id", "")
        channel = e.get("channel", "")
        parts = [f"type={mtype}"]
        if recipient:
            parts.append(f"to={recipient}")
        if channel:
            parts.append(f"ch={channel}")
        return " ".join(parts)
    if src == "transcripts":
        tool = e.get("claimed_tool", "?")
        return f"claimed_tool={tool}"
    if src == "control_plane":
        tool = e.get("actual_tool", "?")
        effect = e.get("effect", "?")
        return f"actual_tool={tool} effect={effect}"
    return ""


def format_json(events: list[dict]) -> str:
    return json.dumps(events, indent=2, sort_keys=True, default=str) + "\n"
