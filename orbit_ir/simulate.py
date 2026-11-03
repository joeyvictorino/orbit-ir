"""Synthetic evidence generator for testing detection pipelines."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCENARIOS = {
    "normal": "Clean traffic with no anomalies",
    "tool_mismatch": "Agents claim one tool but use another",
    "lateral_movement": "Agent communicates with an unusual number of peers",
    "privilege_escalation": "Agent uses high-privilege tools after starting with low-privilege ones",
    "data_exfiltration": "Agent reads sensitive data then sends it externally",
}

_TOOLS_SAFE = ["http_get", "file_read", "db_query", "send_message", "log_write"]
_TOOLS_DANGEROUS = ["shell_exec", "file_write", "admin_api", "credential_read"]

_BASE_TIME = datetime(2026, 7, 15, 10, 0, 0, tzinfo=timezone.utc)


def _agent_id(n: int) -> str:
    return f"agent_{n:03d}"


def _ts(offset_seconds: int) -> str:
    return (_BASE_TIME + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def generate_evidence(
    output_dir: Path,
    scenario: str,
    num_agents: int = 3,
    num_events: int = 20,
    seed: int = 42,
) -> dict:
    """Generate synthetic evidence for a given scenario.

    Returns a summary dict with file paths, counts, and planted anomalies.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scenario = scenario.lower()
    if scenario not in SCENARIOS:
        raise ValueError(
            f"unknown scenario: {scenario!r}, must be one of {list(SCENARIOS.keys())}"
        )

    rng = random.Random(seed)
    agents = [_agent_id(i) for i in range(num_agents)]
    planted_anomalies: list[str] = []

    messages: list[dict] = []
    transcripts: list[dict] = []
    control_plane: list[dict] = []

    events_per_type = max(1, num_events // 3)

    for i in range(events_per_type):
        sender = rng.choice(agents)
        recipient = rng.choice([a for a in agents if a != sender]) if num_agents > 1 else None
        messages.append({
            "event_id": f"m{i:04d}",
            "timestamp": _ts(i * 7),
            "agent_id": sender,
            "recipient_agent_id": recipient,
        })

    for i in range(events_per_type):
        agent = rng.choice(agents)
        tool = rng.choice(_TOOLS_SAFE)
        claimed = tool
        actual = tool

        if scenario == "tool_mismatch" and i % 3 == 0:
            actual = rng.choice(_TOOLS_DANGEROUS)
            planted_anomalies.append(
                f"tool_mismatch: agent={agent} claimed={claimed} actual={actual} call_id=c{i:04d}"
            )

        transcripts.append({
            "call_id": f"c{i:04d}",
            "timestamp": _ts(i * 7 + 2),
            "agent_id": agent,
            "claimed_tool": claimed,
            "actual_tool": actual,
        })

    for i in range(events_per_type):
        agent = rng.choice(agents)
        tool = rng.choice(_TOOLS_SAFE)
        control_plane.append({
            "event_id": f"cp{i:04d}",
            "timestamp": _ts(i * 7 + 4),
            "agent_id": agent,
            "tool": tool,
        })

    if scenario == "lateral_movement":
        hub = agents[0]
        for i, target in enumerate(agents[1:]):
            for j in range(5):
                idx = events_per_type + i * 5 + j
                messages.append({
                    "event_id": f"m{idx:04d}",
                    "timestamp": _ts(idx * 3 + 1000),
                    "agent_id": hub,
                    "recipient_agent_id": target,
                })
        planted_anomalies.append(
            f"lateral_movement: hub={hub} contacted {len(agents) - 1} unique peers"
        )

    if scenario == "privilege_escalation":
        escalator = agents[0]
        for i, tool in enumerate(_TOOLS_DANGEROUS):
            idx = events_per_type + i
            transcripts.append({
                "call_id": f"c{idx:04d}",
                "timestamp": _ts(idx * 5 + 2000),
                "agent_id": escalator,
                "claimed_tool": tool,
                "actual_tool": tool,
            })
            control_plane.append({
                "event_id": f"cp{idx:04d}",
                "timestamp": _ts(idx * 5 + 2001),
                "agent_id": escalator,
                "tool": tool,
            })
        planted_anomalies.append(
            f"privilege_escalation: agent={escalator} used {len(_TOOLS_DANGEROUS)} dangerous tools"
        )

    if scenario == "data_exfiltration":
        exfil_agent = agents[-1]
        read_idx = events_per_type + 100
        transcripts.append({
            "call_id": f"c{read_idx:04d}",
            "timestamp": _ts(3000),
            "agent_id": exfil_agent,
            "claimed_tool": "db_query",
            "actual_tool": "credential_read",
        })
        send_idx = read_idx + 1
        transcripts.append({
            "call_id": f"c{send_idx:04d}",
            "timestamp": _ts(3005),
            "agent_id": exfil_agent,
            "claimed_tool": "send_message",
            "actual_tool": "http_post",
        })
        planted_anomalies.append(
            f"data_exfiltration: agent={exfil_agent} read credentials then sent data externally"
        )

    _write_jsonl(output_dir / "messages.jsonl", messages)
    _write_jsonl(output_dir / "transcripts.jsonl", transcripts)
    _write_jsonl(output_dir / "control_plane.jsonl", control_plane)

    return {
        "scenario": scenario,
        "description": SCENARIOS[scenario],
        "num_agents": num_agents,
        "seed": seed,
        "files": {
            "messages": len(messages),
            "transcripts": len(transcripts),
            "control_plane": len(control_plane),
        },
        "planted_anomalies": planted_anomalies,
        "total_events": len(messages) + len(transcripts) + len(control_plane),
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def list_scenarios() -> dict[str, str]:
    """Return available scenario names and descriptions."""
    return dict(SCENARIOS)


def format_simulate_text(result: dict) -> str:
    """Human-readable simulation summary."""
    lines = [
        f"Simulation: {result['scenario']} ({result['description']})",
        f"  Agents:    {result['num_agents']}",
        f"  Seed:      {result['seed']}",
        f"  Events:    {result['total_events']}",
        f"  Messages:  {result['files']['messages']}",
        f"  Transcripts: {result['files']['transcripts']}",
        f"  Control:   {result['files']['control_plane']}",
    ]
    if result["planted_anomalies"]:
        lines.append(f"  Planted anomalies ({len(result['planted_anomalies'])}):")
        for a in result["planted_anomalies"]:
            lines.append(f"    - {a}")
    else:
        lines.append("  No anomalies planted (clean scenario)")
    lines.append("")
    return "\n".join(lines) + "\n"
