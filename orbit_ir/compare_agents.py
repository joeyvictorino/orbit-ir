"""Side-by-side comparison of two agents' behavior across an incident."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .stats import EVIDENCE_FILES


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _agent_stats(rows_by_source: dict[str, list[dict]], agent_id: str) -> dict:
    msgs = rows_by_source.get("messages", [])
    transcripts = rows_by_source.get("transcripts", [])
    cp = rows_by_source.get("control_plane", [])

    agent_msgs = [m for m in msgs if m.get("agent_id") == agent_id]
    received_msgs = [m for m in msgs if m.get("recipient_agent_id") == agent_id]

    agent_transcripts = [t for t in transcripts if t.get("agent_id") == agent_id]
    agent_cp = [e for e in cp if e.get("agent_id") == agent_id]

    tools_claimed = Counter(t.get("claimed_tool", "") for t in agent_transcripts)
    tools_actual = Counter(t.get("actual_tool", "") for t in agent_transcripts if t.get("actual_tool"))
    mismatches = sum(
        1 for t in agent_transcripts
        if t.get("claimed_tool") and t.get("actual_tool") and t["claimed_tool"] != t["actual_tool"]
    )

    timestamps = sorted(
        m.get("timestamp", "") for m in agent_msgs if m.get("timestamp")
    )

    contacts = set()
    for m in agent_msgs:
        if m.get("recipient_agent_id"):
            contacts.add(m["recipient_agent_id"])
    for m in received_msgs:
        if m.get("agent_id"):
            contacts.add(m["agent_id"])

    return {
        "agent_id": agent_id,
        "messages_sent": len(agent_msgs),
        "messages_received": len(received_msgs),
        "transcript_calls": len(agent_transcripts),
        "control_plane_events": len(agent_cp),
        "tools_claimed": dict(tools_claimed.most_common()),
        "tools_actual": dict(tools_actual.most_common()),
        "tool_mismatches": mismatches,
        "unique_contacts": sorted(contacts),
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
    }


def compare_agents(evidence_dir: Path, agent_a: str, agent_b: str) -> dict:
    """Compare two agents side-by-side across all evidence sources."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    rows_by_source: dict[str, list[dict]] = {}
    source_names = {"messages.jsonl": "messages", "transcripts.jsonl": "transcripts", "control_plane.jsonl": "control_plane"}
    for fname, key in source_names.items():
        rows_by_source[key] = _load_jsonl(evidence_dir / fname)

    all_agents: set[str] = set()
    for rows in rows_by_source.values():
        for row in rows:
            if "agent_id" in row:
                all_agents.add(row["agent_id"])
            if "recipient_agent_id" in row and row["recipient_agent_id"]:
                all_agents.add(row["recipient_agent_id"])

    if agent_a not in all_agents:
        raise ValueError(f"agent {agent_a!r} not found in evidence")
    if agent_b not in all_agents:
        raise ValueError(f"agent {agent_b!r} not found in evidence")

    stats_a = _agent_stats(rows_by_source, agent_a)
    stats_b = _agent_stats(rows_by_source, agent_b)

    differences: list[dict] = []
    for metric in ("messages_sent", "messages_received", "transcript_calls", "control_plane_events", "tool_mismatches"):
        va = stats_a[metric]
        vb = stats_b[metric]
        if va != vb:
            differences.append({
                "metric": metric,
                "agent_a": va,
                "agent_b": vb,
                "delta": vb - va,
            })

    tools_a = set(stats_a["tools_claimed"].keys())
    tools_b = set(stats_b["tools_claimed"].keys())
    only_a = sorted(tools_a - tools_b)
    only_b = sorted(tools_b - tools_a)
    if only_a:
        differences.append({"metric": "tools_only_in_a", "tools": only_a})
    if only_b:
        differences.append({"metric": "tools_only_in_b", "tools": only_b})

    contacts_a = set(stats_a["unique_contacts"])
    contacts_b = set(stats_b["unique_contacts"])
    shared_contacts = sorted(contacts_a & contacts_b)

    return {
        "agent_a": stats_a,
        "agent_b": stats_b,
        "differences": differences,
        "shared_contacts": shared_contacts,
    }


def format_comparison_text(comparison: dict) -> str:
    a = comparison["agent_a"]
    b = comparison["agent_b"]

    lines = [
        f"Agent Comparison: {a['agent_id']} vs {b['agent_id']}",
        "",
        f"  {'Metric':<25} {a['agent_id']:<15} {b['agent_id']:<15}",
        f"  {'-'*25} {'-'*15} {'-'*15}",
        f"  {'Messages sent':<25} {a['messages_sent']:<15} {b['messages_sent']:<15}",
        f"  {'Messages received':<25} {a['messages_received']:<15} {b['messages_received']:<15}",
        f"  {'Transcript calls':<25} {a['transcript_calls']:<15} {b['transcript_calls']:<15}",
        f"  {'Control-plane events':<25} {a['control_plane_events']:<15} {b['control_plane_events']:<15}",
        f"  {'Tool mismatches':<25} {a['tool_mismatches']:<15} {b['tool_mismatches']:<15}",
        f"  {'Unique contacts':<25} {len(a['unique_contacts']):<15} {len(b['unique_contacts']):<15}",
    ]

    if a["first_seen"] or b["first_seen"]:
        lines.append(f"  {'First seen':<25} {a['first_seen'] or 'N/A':<15} {b['first_seen'] or 'N/A':<15}")
        lines.append(f"  {'Last seen':<25} {a['last_seen'] or 'N/A':<15} {b['last_seen'] or 'N/A':<15}")

    if comparison["differences"]:
        lines.append("")
        lines.append("  Differences:")
        for d in comparison["differences"]:
            if "delta" in d:
                sign = "+" if d["delta"] > 0 else ""
                lines.append(f"    {d['metric']}: {a['agent_id']}={d['agent_a']}, {b['agent_id']}={d['agent_b']} ({sign}{d['delta']})")
            elif "tools" in d:
                lines.append(f"    {d['metric']}: {', '.join(d['tools'])}")

    if comparison["shared_contacts"]:
        lines.append("")
        lines.append(f"  Shared contacts: {', '.join(comparison['shared_contacts'])}")

    return "\n".join(lines) + "\n"
