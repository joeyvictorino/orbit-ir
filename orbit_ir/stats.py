"""Quick summary statistics for an evidence dataset."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")


def evidence_stats(input_dir: Path) -> dict:
    """Compute summary statistics for the evidence in *input_dir*."""
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    file_stats: list[dict] = []
    agents: set[str] = set()
    tools: set[str] = set()
    timestamps: list[str] = []
    message_count = 0
    transcript_count = 0
    control_count = 0

    for name in EVIDENCE_FILES:
        path = input_dir / name
        if not path.exists():
            file_stats.append({"name": name, "lines": 0, "bytes": 0, "present": False})
            continue
        size = path.stat().st_size
        count = 0
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if name == "messages.jsonl":
                    if "agent_id" in row:
                        agents.add(row["agent_id"])
                    if "recipient_agent_id" in row and row["recipient_agent_id"]:
                        agents.add(row["recipient_agent_id"])
                    if "timestamp" in row:
                        timestamps.append(row["timestamp"])
                elif name == "transcripts.jsonl":
                    if "agent_id" in row:
                        agents.add(row["agent_id"])
                    if "claimed_tool" in row:
                        tools.add(row["claimed_tool"])
                    if "actual_tool" in row and row["actual_tool"]:
                        tools.add(row["actual_tool"])
                elif name == "control_plane.jsonl":
                    if "agent_id" in row:
                        agents.add(row["agent_id"])
                    if "tool" in row:
                        tools.add(row["tool"])

        file_stats.append({"name": name, "lines": count, "bytes": size, "present": True})

        if name == "messages.jsonl":
            message_count = count
        elif name == "transcripts.jsonl":
            transcript_count = count
        elif name == "control_plane.jsonl":
            control_count = count

    timestamps.sort()
    time_range = {}
    if timestamps:
        time_range = {"earliest": timestamps[0], "latest": timestamps[-1]}

    has_ground_truth = (input_dir / "ground_truth.json").exists()

    return {
        "directory": str(input_dir),
        "agents": len(agents),
        "messages": message_count,
        "transcripts": transcript_count,
        "control_plane_events": control_count,
        "unique_tools": sorted(tools),
        "time_range": time_range,
        "has_ground_truth": has_ground_truth,
        "files": file_stats,
    }


def format_stats_text(s: dict) -> str:
    """Human-readable summary."""
    lines = [
        f"Evidence: {s['directory']}",
        f"  Agents:               {s['agents']}",
        f"  Messages:             {s['messages']}",
        f"  Transcripts:          {s['transcripts']}",
        f"  Control-plane events: {s['control_plane_events']}",
        f"  Unique tools:         {len(s['unique_tools'])}",
    ]
    if s["time_range"]:
        lines.append(f"  Time range:           {s['time_range']['earliest']} .. {s['time_range']['latest']}")
    lines.append(f"  Ground truth:         {'yes' if s['has_ground_truth'] else 'no'}")
    for f in s["files"]:
        mark = "OK" if f["present"] else "MISSING"
        lines.append(f"  [{mark}] {f['name']}: {f['lines']} lines, {f['bytes']} bytes")
    return "\n".join(lines) + "\n"
