"""Customizable analysis report generator.

Combines multiple analysis passes into a single configurable report
with selectable sections and severity filtering.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .stats import evidence_stats
from .replay import replay_events

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ALL_SECTIONS = ("summary", "findings", "agents", "timeline", "tools", "recommendations")


@dataclass
class ReportConfig:
    title: str = "Orbit-IR Analysis Report"
    sections: list[str] = field(default_factory=lambda: list(_ALL_SECTIONS))
    include_charts: bool = False
    severity_threshold: str | None = None
    format: str = "text"


def generate_report(evidence_dir: Path, config: ReportConfig | None = None) -> str:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    if config is None:
        config = ReportConfig()

    stats = evidence_stats(evidence_dir)
    events = _load_events(evidence_dir)
    findings = _extract_findings(events, stats)

    if config.severity_threshold:
        threshold = _SEVERITY_ORDER.get(config.severity_threshold.lower(), 3)
        findings = [f for f in findings if _SEVERITY_ORDER.get(f.get("severity", "low"), 3) <= threshold]

    parts: list[str] = []
    is_md = config.format == "markdown"

    if is_md:
        parts.append(f"# {config.title}\n")
    else:
        parts.append(f"{config.title}")
        parts.append("=" * len(config.title))

    for section in config.sections:
        if section == "summary":
            parts.append(_render_summary(stats, findings, is_md))
        elif section == "findings":
            parts.append(_render_findings(findings, is_md))
        elif section == "agents":
            parts.append(_render_agents(stats, events, is_md))
        elif section == "timeline":
            parts.append(_render_timeline(evidence_dir, is_md))
        elif section == "tools":
            parts.append(_render_tools(stats, events, is_md))
        elif section == "recommendations":
            parts.append(_render_recommendations(findings, stats, is_md))

    return "\n".join(parts) + "\n"


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    for name in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl"):
        path = evidence_dir / name
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    row["_source"] = name
                    events.append(row)
                except json.JSONDecodeError:
                    continue
    return events


def _extract_findings(events: list[dict], stats: dict) -> list[dict]:
    findings: list[dict] = []

    tools_by_agent: dict[str, dict[str, set[str]]] = {}
    for e in events:
        if e.get("_source") != "transcripts.jsonl":
            continue
        agent = e.get("agent_id", "")
        claimed = e.get("claimed_tool", "")
        actual = e.get("actual_tool", "")
        if agent not in tools_by_agent:
            tools_by_agent[agent] = {"claimed": set(), "actual": set()}
        if claimed:
            tools_by_agent[agent]["claimed"].add(claimed)
        if actual:
            tools_by_agent[agent]["actual"].add(actual)

        if claimed and actual and claimed != actual:
            findings.append({
                "type": "tool_mismatch",
                "severity": "high",
                "agent_id": agent,
                "description": f"Agent {agent} claimed tool '{claimed}' but used '{actual}'",
                "evidence": {"call_id": e.get("call_id", ""), "claimed_tool": claimed, "actual_tool": actual},
            })

    msg_counts: dict[str, int] = {}
    contacts: dict[str, set[str]] = {}
    for e in events:
        if e.get("_source") != "messages.jsonl":
            continue
        agent = e.get("agent_id", "")
        msg_counts[agent] = msg_counts.get(agent, 0) + 1
        recipient = e.get("recipient_agent_id")
        if recipient:
            contacts.setdefault(agent, set()).add(recipient)

    if msg_counts:
        avg = sum(msg_counts.values()) / len(msg_counts)
        for agent, count in msg_counts.items():
            if count > avg * 3 and count > 5:
                findings.append({
                    "type": "high_activity",
                    "severity": "medium",
                    "agent_id": agent,
                    "description": f"Agent {agent} sent {count} messages (avg {avg:.0f})",
                    "evidence": {"message_count": count, "average": round(avg, 1)},
                })

    return findings


def _render_summary(stats: dict, findings: list[dict], is_md: bool) -> str:
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    tr = stats.get("time_range", {})
    earliest = tr.get("earliest", "N/A")
    latest = tr.get("latest", "N/A")

    if is_md:
        lines = [
            "\n## Summary\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Agents | {stats.get('agents', 0)} |",
            f"| Messages | {stats.get('messages', 0)} |",
            f"| Transcripts | {stats.get('transcripts', 0)} |",
            f"| Findings | {len(findings)} |",
            f"| Time Range | {earliest} — {latest} |",
            "",
            "**Severity Breakdown:**",
        ]
        for sev in ("critical", "high", "medium", "low"):
            if sev_counts[sev] > 0:
                lines.append(f"- **{sev.upper()}**: {sev_counts[sev]}")
    else:
        lines = [
            "\nSummary",
            "-------",
            f"  Agents:       {stats.get('agents', 0)}",
            f"  Messages:     {stats.get('messages', 0)}",
            f"  Transcripts:  {stats.get('transcripts', 0)}",
            f"  Findings:     {len(findings)}",
            f"  Time Range:   {earliest} — {latest}",
            "",
            "  Severity Breakdown:",
        ]
        for sev in ("critical", "high", "medium", "low"):
            if sev_counts[sev] > 0:
                lines.append(f"    {sev.upper()}: {sev_counts[sev]}")

    return "\n".join(lines)


def _render_findings(findings: list[dict], is_md: bool) -> str:
    if not findings:
        if is_md:
            return "\n## Findings\n\nNo findings detected."
        return "\nFindings\n--------\n  No findings detected."

    grouped: dict[str, list[dict]] = {}
    for f in findings:
        sev = f.get("severity", "low")
        grouped.setdefault(sev, []).append(f)

    if is_md:
        lines = ["\n## Findings\n"]
        for sev in ("critical", "high", "medium", "low"):
            group = grouped.get(sev, [])
            if not group:
                continue
            lines.append(f"\n### {sev.upper()} ({len(group)})\n")
            for f in group:
                lines.append(f"- **{f['type']}** — {f['description']}")
    else:
        lines = ["\nFindings", "--------"]
        for sev in ("critical", "high", "medium", "low"):
            group = grouped.get(sev, [])
            if not group:
                continue
            lines.append(f"\n  {sev.upper()} ({len(group)}):")
            for f in group:
                lines.append(f"    [{f['type']}] {f['description']}")

    return "\n".join(lines)


def _render_agents(stats: dict, events: list[dict], is_md: bool) -> str:
    agent_msgs: dict[str, int] = {}
    agent_tools: dict[str, set[str]] = {}
    agent_contacts: dict[str, set[str]] = {}

    for e in events:
        agent = e.get("agent_id", "")
        if not agent:
            continue
        if e.get("_source") == "messages.jsonl":
            agent_msgs[agent] = agent_msgs.get(agent, 0) + 1
            recipient = e.get("recipient_agent_id")
            if recipient:
                agent_contacts.setdefault(agent, set()).add(recipient)
        elif e.get("_source") == "transcripts.jsonl":
            tool = e.get("claimed_tool") or e.get("actual_tool", "")
            if tool:
                agent_tools.setdefault(agent, set()).add(tool)

    all_agents = sorted(set(list(agent_msgs.keys()) + list(agent_tools.keys())))

    if is_md:
        lines = ["\n## Agents\n"]
        if not all_agents:
            lines.append("No agents found.")
        else:
            lines.append("| Agent | Messages | Tools | Contacts |")
            lines.append("|-------|----------|-------|----------|")
            for a in all_agents:
                msgs = agent_msgs.get(a, 0)
                tools = len(agent_tools.get(a, set()))
                conts = len(agent_contacts.get(a, set()))
                lines.append(f"| {a} | {msgs} | {tools} | {conts} |")
    else:
        lines = ["\nAgents", "------"]
        if not all_agents:
            lines.append("  No agents found.")
        else:
            for a in all_agents:
                msgs = agent_msgs.get(a, 0)
                tools = sorted(agent_tools.get(a, set()))
                conts = sorted(agent_contacts.get(a, set()))
                lines.append(f"  {a}:")
                lines.append(f"    Messages: {msgs}")
                if tools:
                    lines.append(f"    Tools: {', '.join(tools)}")
                if conts:
                    lines.append(f"    Contacts: {', '.join(conts)}")

    return "\n".join(lines)


def _render_timeline(evidence_dir: Path, is_md: bool) -> str:
    try:
        events = replay_events(evidence_dir, annotate=True)
    except Exception:
        events = []

    if is_md:
        lines = ["\n## Timeline\n"]
        if not events:
            lines.append("No events to display.")
        else:
            shown = events[:20]
            for e in shown:
                ts = e.get("timestamp", "?")
                agent = e.get("agent_id", "?")
                source = e.get("_source", "?")
                annotations = e.get("annotations", [])
                ann_str = f" [{', '.join(annotations)}]" if annotations else ""
                lines.append(f"- `{ts}` **{agent}** ({source}){ann_str}")
            if len(events) > 20:
                lines.append(f"\n*...and {len(events) - 20} more events*")
    else:
        lines = ["\nTimeline", "--------"]
        if not events:
            lines.append("  No events to display.")
        else:
            shown = events[:20]
            for e in shown:
                ts = e.get("timestamp", "?")
                agent = e.get("agent_id", "?")
                source = e.get("_source", "?")
                annotations = e.get("annotations", [])
                ann_str = f" [{', '.join(annotations)}]" if annotations else ""
                lines.append(f"  {ts}  {agent}  ({source}){ann_str}")
            if len(events) > 20:
                lines.append(f"\n  ...and {len(events) - 20} more events")

    return "\n".join(lines)


def _render_tools(stats: dict, events: list[dict], is_md: bool) -> str:
    tool_usage: dict[str, int] = {}
    mismatches: dict[str, int] = {}

    for e in events:
        if e.get("_source") != "transcripts.jsonl":
            continue
        claimed = e.get("claimed_tool", "")
        actual = e.get("actual_tool", "")
        if claimed:
            tool_usage[claimed] = tool_usage.get(claimed, 0) + 1
        if claimed and actual and claimed != actual:
            key = f"{claimed} -> {actual}"
            mismatches[key] = mismatches.get(key, 0) + 1

    unique_tools = sorted(stats.get("unique_tools", []))

    if is_md:
        lines = ["\n## Tools\n"]
        lines.append(f"**Unique tools:** {len(unique_tools)}")
        if unique_tools:
            lines.append("")
            lines.append("| Tool | Usage Count |")
            lines.append("|------|-------------|")
            for tool in sorted(tool_usage, key=lambda t: tool_usage[t], reverse=True):
                lines.append(f"| {tool} | {tool_usage[tool]} |")
        if mismatches:
            lines.append(f"\n**Tool Mismatches:** {sum(mismatches.values())}")
            for mismatch, count in sorted(mismatches.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- {mismatch}: {count}")
    else:
        lines = ["\nTools", "-----"]
        lines.append(f"  Unique tools: {len(unique_tools)}")
        if tool_usage:
            lines.append("")
            for tool in sorted(tool_usage, key=lambda t: tool_usage[t], reverse=True):
                lines.append(f"  {tool}: {tool_usage[tool]} uses")
        if mismatches:
            lines.append(f"\n  Tool Mismatches: {sum(mismatches.values())}")
            for mismatch, count in sorted(mismatches.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"    {mismatch}: {count}")

    return "\n".join(lines)


def _render_recommendations(findings: list[dict], stats: dict, is_md: bool) -> str:
    recs: list[str] = []

    type_counts: dict[str, int] = {}
    agents_with_findings: set[str] = set()
    for f in findings:
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
        if "agent_id" in f:
            agents_with_findings.add(f["agent_id"])

    if type_counts.get("tool_mismatch", 0) > 0:
        recs.append("Investigate tool mismatches — agents claimed different tools than actually used")
    if type_counts.get("high_activity", 0) > 0:
        recs.append("Review high-activity agents for potential automated or compromised behavior")
    if agents_with_findings:
        top = sorted(agents_with_findings)[:3]
        recs.append(f"Priority agents for review: {', '.join(top)}")
    if not findings:
        recs.append("No anomalies detected — consider broadening detection rules or increasing data collection")

    if is_md:
        lines = ["\n## Recommendations\n"]
        for r in recs:
            lines.append(f"1. {r}")
    else:
        lines = ["\nRecommendations", "---------------"]
        for i, r in enumerate(recs, 1):
            lines.append(f"  {i}. {r}")

    return "\n".join(lines)
