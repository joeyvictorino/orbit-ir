"""Apply investigation scope filters to evidence before analysis.

Filters evidence JSONL files by time window, agent set, or event source,
writing a reduced evidence directory for focused analysis.
"""

from __future__ import annotations

import json
from pathlib import Path


_SOURCE_FILES = {
    "messages": "messages.jsonl",
    "transcripts": "transcripts.jsonl",
    "control_plane": "control_plane.jsonl",
}


def _in_time_window(ts: str | None, start: str | None, end: str | None) -> bool:
    if ts is None:
        return True
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def _matches_agent(record: dict, agents: set[str] | None) -> bool:
    if agents is None:
        return True
    record_agent = record.get("agent_id") or ""
    if record_agent in agents:
        return True
    if record.get("agent_id_transcript") in agents:
        return True
    if record.get("agent_id_control") in agents:
        return True
    return False


def apply_scope(
    input_dir: Path,
    output_dir: Path,
    *,
    start: str | None = None,
    end: str | None = None,
    agents: list[str] | None = None,
    sources: list[str] | None = None,
) -> dict:
    if not input_dir.is_dir():
        raise FileNotFoundError(f"evidence directory not found: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    agent_set = set(agents) if agents else None
    source_set = set(sources) if sources else None

    total_before = 0
    total_after = 0
    file_stats: dict[str, dict] = {}

    for source_key, filename in _SOURCE_FILES.items():
        src = input_dir / filename
        if not src.exists():
            continue

        if source_set and source_key not in source_set:
            file_stats[source_key] = {"before": 0, "after": 0, "skipped": True}
            continue

        before = 0
        after = 0
        kept: list[str] = []

        with src.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                before += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts = record.get("timestamp")
                if not _in_time_window(ts, start, end):
                    continue
                if not _matches_agent(record, agent_set):
                    continue

                after += 1
                kept.append(json.dumps(record, sort_keys=True))

        dst = output_dir / filename
        dst.write_text("\n".join(kept) + "\n" if kept else "", encoding="utf-8")
        total_before += before
        total_after += after
        file_stats[source_key] = {"before": before, "after": after}

    gt = input_dir / "ground_truth.json"
    if gt.exists():
        (output_dir / "ground_truth.json").write_text(
            gt.read_text(encoding="utf-8"), encoding="utf-8"
        )

    filters_applied: list[str] = []
    if start:
        filters_applied.append(f"start>={start}")
    if end:
        filters_applied.append(f"end<={end}")
    if agents:
        filters_applied.append(f"agents={','.join(agents)}")
    if sources:
        filters_applied.append(f"sources={','.join(sources)}")

    return {
        "total_before": total_before,
        "total_after": total_after,
        "filters_applied": filters_applied,
        "files": file_stats,
    }
