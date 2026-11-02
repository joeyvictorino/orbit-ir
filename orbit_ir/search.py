"""Search evidence JSONL files for events matching criteria."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator


def search_evidence(
    path: str | Path,
    *,
    query: str | None = None,
    agent: str | None = None,
    action: str | None = None,
    after: str | None = None,
    before: str | None = None,
) -> list[dict]:
    """Search a JSONL evidence file for matching events."""
    results = []
    for event in _iter_matches(path, query=query, agent=agent, action=action, after=after, before=before):
        results.append(event)
    return results


def _iter_matches(
    path: str | Path,
    *,
    query: str | None = None,
    agent: str | None = None,
    action: str | None = None,
    after: str | None = None,
    before: str | None = None,
) -> Iterator[dict]:
    path = Path(path)
    after_dt = _parse_ts(after) if after else None
    before_dt = _parse_ts(before) if before else None
    pattern = re.compile(query, re.IGNORECASE) if query else None

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if agent and event.get("agent") != agent:
            continue
        if action and event.get("action") != action:
            continue

        ts = event.get("timestamp") or event.get("ts")
        if ts and (after_dt or before_dt):
            event_dt = _parse_ts(ts)
            if event_dt:
                if after_dt and event_dt < after_dt:
                    continue
                if before_dt and event_dt > before_dt:
                    continue

        if pattern:
            text = json.dumps(event, default=str)
            if not pattern.search(text):
                continue

        yield event


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def format_search_text(results: list[dict]) -> str:
    if not results:
        return "No matching events found.\n"
    lines = [f"Found {len(results)} matching event(s):\n"]
    for i, event in enumerate(results, 1):
        agent = event.get("agent", "?")
        action = event.get("action", "?")
        ts = event.get("timestamp", event.get("ts", "?"))
        lines.append(f"  {i}. [{ts}] {agent} -> {action}")
        detail = event.get("detail") or event.get("details") or event.get("description")
        if detail:
            lines.append(f"     {detail}")
    return "\n".join(lines) + "\n"
