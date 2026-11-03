"""Agent behavior fingerprinting for anomaly detection."""

from __future__ import annotations

import json
import math
from pathlib import Path


def fingerprint_agents(input_dir: Path) -> dict:
    """Compute behavior fingerprints for each agent in the evidence.

    Returns a dict with per-agent profiles and anomaly scores.
    """
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    agents: dict[str, dict] = {}

    _process_messages(input_dir, agents)
    _process_transcripts(input_dir, agents)
    _process_control_plane(input_dir, agents)

    profiles = {}
    for aid, data in agents.items():
        profiles[aid] = _build_profile(aid, data)

    if profiles:
        _compute_anomaly_scores(profiles)

    return {
        "agent_count": len(profiles),
        "profiles": profiles,
    }


def _process_messages(input_dir: Path, agents: dict) -> None:
    path = input_dir / "messages.jsonl"
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = row.get("agent_id", "")
            if not aid:
                continue
            if aid not in agents:
                agents[aid] = _empty_agent()
            agents[aid]["messages_sent"] += 1
            recipient = row.get("recipient_agent_id")
            if recipient:
                agents[aid]["unique_recipients"].add(recipient)
                if recipient not in agents:
                    agents[recipient] = _empty_agent()
            ts = row.get("timestamp", "")
            if ts:
                agents[aid]["timestamps"].append(ts)


def _process_transcripts(input_dir: Path, agents: dict) -> None:
    path = input_dir / "transcripts.jsonl"
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = row.get("agent_id", "")
            if not aid:
                continue
            if aid not in agents:
                agents[aid] = _empty_agent()
            agents[aid]["tool_calls"] += 1
            claimed = row.get("claimed_tool", "")
            actual = row.get("actual_tool", "")
            if claimed:
                agents[aid]["tools_used"].add(claimed)
            if actual and actual != claimed:
                agents[aid]["tool_mismatches"] += 1


def _process_control_plane(input_dir: Path, agents: dict) -> None:
    path = input_dir / "control_plane.jsonl"
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = row.get("agent_id", "")
            if not aid:
                continue
            if aid not in agents:
                agents[aid] = _empty_agent()
            agents[aid]["control_plane_events"] += 1


def _empty_agent() -> dict:
    return {
        "messages_sent": 0,
        "unique_recipients": set(),
        "timestamps": [],
        "tool_calls": 0,
        "tools_used": set(),
        "tool_mismatches": 0,
        "control_plane_events": 0,
    }


def _build_profile(aid: str, data: dict) -> dict:
    return {
        "agent_id": aid,
        "messages_sent": data["messages_sent"],
        "unique_recipients": len(data["unique_recipients"]),
        "tool_calls": data["tool_calls"],
        "unique_tools": len(data["tools_used"]),
        "tool_mismatch_rate": (
            data["tool_mismatches"] / data["tool_calls"]
            if data["tool_calls"] > 0
            else 0.0
        ),
        "control_plane_events": data["control_plane_events"],
        "anomaly_score": 0.0,
    }


def _compute_anomaly_scores(profiles: dict) -> None:
    """Score each agent by deviation from the population mean.

    Uses a simple z-score across numeric features; agents with high
    composite deviation are flagged as anomalous.
    """
    features = [
        "messages_sent",
        "unique_recipients",
        "tool_calls",
        "unique_tools",
        "tool_mismatch_rate",
        "control_plane_events",
    ]

    n = len(profiles)
    if n < 2:
        return

    means: dict[str, float] = {}
    stds: dict[str, float] = {}

    for feat in features:
        vals = [p[feat] for p in profiles.values()]
        mean = sum(vals) / n
        variance = sum((v - mean) ** 2 for v in vals) / n
        means[feat] = mean
        stds[feat] = math.sqrt(variance) if variance > 0 else 0.0

    for profile in profiles.values():
        z_sum = 0.0
        count = 0
        for feat in features:
            if stds[feat] > 0:
                z = abs(profile[feat] - means[feat]) / stds[feat]
                z_sum += z
                count += 1
        profile["anomaly_score"] = round(z_sum / count, 3) if count > 0 else 0.0


def format_fingerprint_text(result: dict) -> str:
    """Human-readable fingerprint summary."""
    lines = [f"Agent behavior fingerprints ({result['agent_count']} agents):"]
    sorted_profiles = sorted(
        result["profiles"].values(),
        key=lambda p: p["anomaly_score"],
        reverse=True,
    )
    for p in sorted_profiles:
        flag = " [ANOMALOUS]" if p["anomaly_score"] >= 2.0 else ""
        lines.append(
            f"  {p['agent_id']}: score={p['anomaly_score']:.1f}{flag}"
            f"  msgs={p['messages_sent']} tools={p['tool_calls']}"
            f"  mismatch={p['tool_mismatch_rate']:.0%}"
        )
    return "\n".join(lines) + "\n"
