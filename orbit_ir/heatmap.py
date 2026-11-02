"""Agent activity heatmap: message volume by agent and time bucket."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def build_heatmap(messages: list[dict], bucket_minutes: int = 60) -> dict:
    """Build an activity heatmap from parsed messages.

    Returns ``{"agents": [...], "buckets": [...], "cells": {(agent, bucket): count}, "bucket_minutes": int}``.
    Each bucket is an ISO timestamp string for the start of the window.
    """
    if bucket_minutes < 1:
        bucket_minutes = 1

    cells: Counter[tuple[str, str]] = Counter()
    agents: set[str] = set()
    buckets: set[str] = set()

    for msg in messages:
        agent = msg.get("agent_id")
        ts_str = msg.get("timestamp")
        if not agent or not ts_str:
            continue
        agents.add(agent)
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        bucket_ts = _truncate(ts, bucket_minutes)
        bucket_key = bucket_ts.isoformat().replace("+00:00", "Z")
        buckets.add(bucket_key)
        cells[(agent, bucket_key)] += 1

    return {
        "agents": sorted(agents),
        "buckets": sorted(buckets),
        "cells": dict(cells),
        "bucket_minutes": bucket_minutes,
    }


def format_heatmap_summary(heatmap: dict) -> dict:
    """Return a JSON-serialisable summary of the heatmap."""
    cells_list = [
        {"agent": agent, "bucket": bucket, "count": count}
        for (agent, bucket), count in sorted(heatmap["cells"].items())
    ]

    agent_totals = Counter()
    bucket_totals = Counter()
    for (agent, bucket), count in heatmap["cells"].items():
        agent_totals[agent] += count
        bucket_totals[bucket] += count

    peak_bucket = max(bucket_totals, key=bucket_totals.get) if bucket_totals else None
    peak_agent = max(agent_totals, key=agent_totals.get) if agent_totals else None

    return {
        "agents": heatmap["agents"],
        "buckets": heatmap["buckets"],
        "bucket_minutes": heatmap["bucket_minutes"],
        "cells": cells_list,
        "total_messages": sum(heatmap["cells"].values()),
        "peak_bucket": peak_bucket,
        "peak_bucket_count": bucket_totals.get(peak_bucket, 0) if peak_bucket else 0,
        "peak_agent": peak_agent,
        "peak_agent_count": agent_totals.get(peak_agent, 0) if peak_agent else 0,
        "agent_totals": dict(sorted(agent_totals.items())),
        "bucket_totals": dict(sorted(bucket_totals.items())),
    }


def load_and_build_heatmap(input_dir: Path, bucket_minutes: int = 60) -> dict:
    """Load messages.jsonl from a directory and build the heatmap."""
    messages_path = input_dir / "messages.jsonl"
    messages: list[dict] = []
    if messages_path.exists():
        with messages_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    messages.append(json.loads(line))
    return build_heatmap(messages, bucket_minutes)


def _truncate(ts: datetime, bucket_minutes: int) -> datetime:
    """Truncate a timestamp to the nearest bucket boundary."""
    total_minutes = ts.hour * 60 + ts.minute
    bucket_start = (total_minutes // bucket_minutes) * bucket_minutes
    return ts.replace(
        hour=bucket_start // 60,
        minute=bucket_start % 60,
        second=0,
        microsecond=0,
    )
