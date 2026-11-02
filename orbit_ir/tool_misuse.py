"""Tool misuse classification for agent evidence.

Analyzes agent events for tool usage that deviates from expected
patterns—using write tools on read-only resources, network tools to
unexpected endpoints, suspicious tool chains, and unusual parameters.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MISUSE_TYPES = {
    "accidental": "Wrong tool used for the task",
    "exploratory": "Probing tool capabilities beyond need",
    "intentional": "Deliberate misuse of a legitimate tool",
    "evasive": "Using legitimate tools to avoid detection",
}

WRITE_TOOLS = {
    "write_file", "create_file", "delete_file", "modify_file",
    "update_record", "insert_record", "delete_record", "drop_table",
    "create_table", "write_config", "set_env",
}

READ_TOOLS = {
    "read_file", "list_directory", "search_files", "query_db",
    "get_record", "read_config", "get_env", "list_tables",
}

NETWORK_TOOLS = {
    "http_get", "http_post", "http_put", "http_delete",
    "api_call", "send_request", "fetch_url", "curl",
    "send_email", "webhook", "dns_lookup",
}

SYSTEM_TOOLS = {
    "execute_command", "run_shell", "spawn_process", "kill_process",
    "modify_cron", "create_service", "restart_service",
    "install_package", "set_permission",
}

SUSPICIOUS_SEQUENCES = [
    ({"read_file", "search_files", "list_directory"}, {"http_post", "send_email", "upload_file", "webhook"}),
    ({"query_db", "dump_table", "read_config"}, {"write_file", "create_file"}),
    ({"execute_command", "run_shell"}, {"modify_cron", "create_service"}),
]


@dataclass
class MisuseDetection:
    detection_id: str
    agent_id: str
    misuse_type: str
    severity: str
    confidence: str
    timestamp: str
    tool: str
    resource: str
    expected_usage: str
    actual_usage: str
    description: str


@dataclass
class AgentToolProfile:
    agent_id: str
    tools_used: dict[str, int]
    total_calls: int
    unique_tools: int
    deviation_score: float
    top_tools: list[str]


@dataclass
class ToolMisuseSummary:
    total_detections: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    tools_flagged: int


@dataclass
class ToolMisuseReport:
    detections: list[MisuseDetection]
    agent_profiles: list[AgentToolProfile]
    deviation_scores: dict[str, float]
    summary: ToolMisuseSummary


def _categorize_tool(tool: str) -> str:
    lower = tool.lower()
    if lower in WRITE_TOOLS or any(k in lower for k in {"write", "create", "delete", "modify", "update", "insert", "drop"}):
        return "write"
    if lower in READ_TOOLS or any(k in lower for k in {"read", "list", "search", "query", "get"}):
        return "read"
    if lower in NETWORK_TOOLS or any(k in lower for k in {"http", "api", "send", "fetch", "curl", "webhook", "dns"}):
        return "network"
    if lower in SYSTEM_TOOLS or any(k in lower for k in {"execute", "shell", "spawn", "kill", "cron", "service", "install"}):
        return "system"
    return "other"


def analyze_tool_misuse(events: list[dict[str, Any]]) -> ToolMisuseReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[MisuseDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_write_on_readonly(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_unexpected_network(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_system_for_data(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_suspicious_chains(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_unusual_params(agent, evts_sorted, detections, det_counter)

    detections.sort(
        key=lambda d: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(d.severity, 4)
    )

    profiles = _build_profiles(agent_events)
    dev_scores = {p.agent_id: p.deviation_score for p in profiles}

    type_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    flagged_tools: set[str] = set()
    for d in detections:
        type_counts[d.misuse_type] += 1
        sev_counts[d.severity] += 1
        conf_counts[d.confidence] += 1
        flagged_tools.add(d.tool)

    return ToolMisuseReport(
        detections=detections,
        agent_profiles=profiles,
        deviation_scores=dev_scores,
        summary=ToolMisuseSummary(
            total_detections=len(detections),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len({d.agent_id for d in detections}),
            tools_flagged=len(flagged_tools),
        ),
    )


def _detect_write_on_readonly(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MisuseDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", "")
        access = ev.get("access_level", ev.get("permission", ""))

        if _categorize_tool(tool) == "write" and access.lower() in ("readonly", "read-only", "ro"):
            counter += 1
            detections.append(
                MisuseDetection(
                    detection_id=f"MISUSE-{counter:03d}",
                    agent_id=agent,
                    misuse_type="intentional",
                    severity="high",
                    confidence="high",
                    timestamp=ev.get("timestamp", ""),
                    tool=tool,
                    resource=resource,
                    expected_usage=f"Read-only access to '{resource}'",
                    actual_usage=f"Write operation '{tool}' on read-only resource",
                    description=(
                        f"Agent '{agent}' used write tool '{tool}' on read-only "
                        f"resource '{resource}'"
                    ),
                )
            )
    return counter


def _detect_unexpected_network(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MisuseDetection],
    counter: int,
) -> int:
    allowed_endpoints = set()
    for ev in events:
        allowed = ev.get("allowed_endpoints", [])
        if isinstance(allowed, list):
            allowed_endpoints.update(allowed)

    if not allowed_endpoints:
        return counter

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("endpoint", ev.get("url", "")))

        if _categorize_tool(tool) == "network" and resource:
            resource_lower = resource.lower()
            in_allowed = any(ep.lower() in resource_lower for ep in allowed_endpoints)
            if not in_allowed:
                counter += 1
                detections.append(
                    MisuseDetection(
                        detection_id=f"MISUSE-{counter:03d}",
                        agent_id=agent,
                        misuse_type="exploratory",
                        severity="medium",
                        confidence="medium",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=resource,
                        expected_usage=f"Network access to allowed endpoints: {', '.join(sorted(allowed_endpoints)[:3])}",
                        actual_usage=f"Network access to unexpected endpoint '{resource}'",
                        description=(
                            f"Agent '{agent}' made network request to unexpected "
                            f"endpoint '{resource}' via '{tool}'"
                        ),
                    )
                )
    return counter


def _detect_system_for_data(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MisuseDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", "")
        purpose = ev.get("purpose", ev.get("task", ""))

        if _categorize_tool(tool) != "system":
            continue

        purpose_lower = (purpose or "").lower()
        resource_lower = (resource or "").lower()
        is_data_task = any(
            k in purpose_lower or k in resource_lower
            for k in {"data", "query", "read", "file", "config", "secret", "credential"}
        )

        if is_data_task:
            counter += 1
            detections.append(
                MisuseDetection(
                    detection_id=f"MISUSE-{counter:03d}",
                    agent_id=agent,
                    misuse_type="evasive",
                    severity="high",
                    confidence="medium",
                    timestamp=ev.get("timestamp", ""),
                    tool=tool,
                    resource=resource,
                    expected_usage=f"Use read/query tools for data access",
                    actual_usage=f"Used system tool '{tool}' for data-related task",
                    description=(
                        f"Agent '{agent}' used system tool '{tool}' for data access "
                        f"instead of appropriate read tools"
                    ),
                )
            )
    return counter


def _detect_suspicious_chains(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MisuseDetection],
    counter: int,
) -> int:
    tools_sequence: list[tuple[str, dict[str, Any]]] = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if tool:
            tools_sequence.append((tool, ev))

    for prereq_set, follow_set in SUSPICIOUS_SEQUENCES:
        prereq_seen: list[dict[str, Any]] = []
        for tool, ev in tools_sequence:
            lower = tool.lower()
            if lower in prereq_set:
                prereq_seen.append(ev)
            elif lower in follow_set and len(prereq_seen) >= 2:
                counter += 1
                chain_tools = [e.get("tool", e.get("claimed_tool", "")) for e in prereq_seen[-3:]]
                chain_tools.append(tool)
                detections.append(
                    MisuseDetection(
                        detection_id=f"MISUSE-{counter:03d}",
                        agent_id=agent,
                        misuse_type="intentional",
                        severity="high",
                        confidence="medium",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=ev.get("resource", ""),
                        expected_usage="Individual tool use within scope",
                        actual_usage=f"Suspicious tool chain: {' -> '.join(chain_tools)}",
                        description=(
                            f"Agent '{agent}' executed suspicious tool chain: "
                            f"{' -> '.join(chain_tools)}"
                        ),
                    )
                )
                prereq_seen = []
    return counter


def _detect_unusual_params(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MisuseDetection],
    counter: int,
) -> int:
    tool_params: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        params = ev.get("parameters", ev.get("params", {}))
        if tool and isinstance(params, dict) and params:
            tool_params[tool].append(params)

    for tool, param_list in tool_params.items():
        if len(param_list) < 3:
            continue

        all_keys: dict[str, int] = defaultdict(int)
        for p in param_list:
            for k in p:
                all_keys[k] += 1

        common_keys = {k for k, c in all_keys.items() if c >= len(param_list) * 0.5}

        for i, params in enumerate(param_list):
            unusual_keys = set(params.keys()) - common_keys
            if len(unusual_keys) >= 2 and len(unusual_keys) > len(common_keys & set(params.keys())):
                ev = events[min(i, len(events) - 1)]
                counter += 1
                detections.append(
                    MisuseDetection(
                        detection_id=f"MISUSE-{counter:03d}",
                        agent_id=agent,
                        misuse_type="exploratory",
                        severity="low",
                        confidence="low",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=ev.get("resource", ""),
                        expected_usage=f"Standard params: {', '.join(sorted(common_keys)[:5])}",
                        actual_usage=f"Unusual params: {', '.join(sorted(unusual_keys)[:5])}",
                        description=(
                            f"Agent '{agent}' used tool '{tool}' with unusual parameters: "
                            f"{', '.join(sorted(unusual_keys)[:5])}"
                        ),
                    )
                )
                break
    return counter


def _build_profiles(
    agent_events: dict[str, list[dict[str, Any]]],
) -> list[AgentToolProfile]:
    global_tool_counts: dict[str, int] = defaultdict(int)
    total_events = 0
    for evts in agent_events.values():
        for ev in evts:
            tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
            if tool:
                global_tool_counts[tool] += 1
                total_events += 1

    global_dist = {t: c / max(total_events, 1) for t, c in global_tool_counts.items()}

    profiles: list[AgentToolProfile] = []
    for agent, evts in sorted(agent_events.items()):
        tool_counts: dict[str, int] = defaultdict(int)
        for ev in evts:
            tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
            if tool:
                tool_counts[tool] += 1

        agent_total = sum(tool_counts.values())
        if agent_total == 0:
            continue

        agent_dist = {t: c / agent_total for t, c in tool_counts.items()}

        kl_div = 0.0
        all_tools = set(agent_dist) | set(global_dist)
        for t in all_tools:
            p = agent_dist.get(t, 0.001)
            q = global_dist.get(t, 0.001)
            if p > 0 and q > 0:
                kl_div += p * math.log(p / q)

        deviation = min(round(kl_div, 3), 1.0)

        top_tools = sorted(tool_counts, key=tool_counts.get, reverse=True)[:5]

        profiles.append(
            AgentToolProfile(
                agent_id=agent,
                tools_used=dict(tool_counts),
                total_calls=agent_total,
                unique_tools=len(tool_counts),
                deviation_score=deviation,
                top_tools=top_tools,
            )
        )

    profiles.sort(key=lambda p: p.deviation_score, reverse=True)
    return profiles


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for name in ("transcripts.jsonl", "control_plane.jsonl", "events.jsonl"):
        p = evidence_dir / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events


def format_text(report: ToolMisuseReport) -> str:
    lines: list[str] = []
    lines.append("Tool Misuse Classification Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Tools flagged:          {s.tools_flagged}")
    lines.append("")

    if s.by_type:
        lines.append("  By Misuse Type:")
        for t, c in sorted(s.by_type.items()):
            desc = MISUSE_TYPES.get(t, t)
            lines.append(f"    {t}: {c} ({desc})")
        lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sv, c in sorted(s.by_severity.items()):
            lines.append(f"    {sv}: {c}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.severity.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Type: {d.misuse_type}")
        lines.append(f"    {d.description}")
        lines.append(f"    Expected: {d.expected_usage}")
        lines.append(f"    Actual: {d.actual_usage}")
        lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    if report.agent_profiles:
        lines.append("  Agent Tool Profiles:")
        lines.append("  " + "-" * 60)
        for p in report.agent_profiles:
            lines.append(
                f"    {p.agent_id}: {p.total_calls} calls, "
                f"{p.unique_tools} tools, deviation={p.deviation_score:.3f}"
            )
            lines.append(f"      Top tools: {', '.join(p.top_tools)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ToolMisuseReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "agent_profiles": [asdict(p) for p in report.agent_profiles],
        "deviation_scores": report.deviation_scores,
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
