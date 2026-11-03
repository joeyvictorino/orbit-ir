"""Tool misuse detection for agent evidence.

Analyzes agent event sequences to detect tool abuse patterns—tools
invoked outside their intended scope, excessive tool call frequency,
unauthorized tool chaining, parameter injection attempts, and tool
calls that deviate from declared agent capabilities.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ABUSE_CATEGORIES = {
    "scope-violation": "Tool invoked outside agent's declared capability scope",
    "excessive-frequency": "Abnormally high tool call rate within time window",
    "unauthorized-chain": "Tool chain that bypasses access controls",
    "parameter-injection": "Tool parameters contain injection payloads",
    "privilege-escalation-tool": "Tool used to escalate agent privileges",
    "shadow-tool": "Undeclared or aliased tool call masking real action",
}

INJECTION_PATTERNS = re.compile(
    r"(\$\{|`.*`|\$\(|;\s*(rm|curl|wget|nc|bash|sh|eval|exec)|"
    r"'.*OR\s+1\s*=\s*1|--\s*$|<script|javascript:|data:text/html|"
    r"\\x[0-9a-f]{2}|%0[ad]|\\u00|{{.*}}|{%.*%})",
    re.IGNORECASE,
)

PRIVILEGE_TOOLS = {
    "sudo", "su", "chmod", "chown", "setuid", "set_permission",
    "grant_access", "add_role", "elevate", "assume_role", "escalate",
    "modify_acl", "write_config", "set_admin", "reset_password",
}

DESTRUCTIVE_TOOLS = {
    "delete_file", "rm", "drop_table", "truncate", "format_disk",
    "kill_process", "shutdown", "wipe", "purge", "destroy",
    "remove_all", "clear_logs", "erase",
}

RECON_TOOLS = {
    "list_directory", "glob_files", "search_files", "enumerate_users",
    "scan_ports", "list_processes", "read_config", "env_dump",
    "list_secrets", "describe_infrastructure", "whoami", "id",
    "list_permissions", "get_credentials",
}


@dataclass
class AbuseDetection:
    detection_id: str
    agent_id: str
    category: str
    confidence: str
    tool: str
    timestamp: str
    events: list[dict[str, Any]]
    description: str
    mitre_technique: str = ""


@dataclass
class AgentToolProfile:
    agent_id: str
    total_calls: int
    unique_tools: int
    abuse_count: int
    top_tools: list[tuple[str, int]]
    declared_tools: list[str]
    undeclared_calls: int


@dataclass
class AbuseSummary:
    total_detections: int
    by_category: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    unique_tools_abused: int
    highest_frequency_agent: str
    highest_frequency_rate: float


@dataclass
class AbuseReport:
    detections: list[AbuseDetection]
    agent_profiles: list[AgentToolProfile]
    summary: AbuseSummary
    timeline: list[dict[str, Any]]


def _is_privilege_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in PRIVILEGE_TOOLS or any(
        k in lower for k in {"sudo", "escalat", "admin", "grant", "elevat"}
    )


def _is_destructive_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in DESTRUCTIVE_TOOLS or any(
        k in lower for k in {"delete", "destroy", "wipe", "purge", "drop", "truncat"}
    )


def _is_recon_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in RECON_TOOLS or any(
        k in lower for k in {"enumerate", "scan", "list_secret", "dump"}
    )


def _has_injection(params: dict[str, Any]) -> bool:
    for v in params.values():
        if isinstance(v, str) and INJECTION_PATTERNS.search(v):
            return True
    return False


def _get_tool(event: dict[str, Any]) -> str:
    return event.get("tool", event.get("claimed_tool", event.get("actual_tool", "")))


def _get_params(event: dict[str, Any]) -> dict[str, Any]:
    p = event.get("parameters", event.get("params", event.get("args", {})))
    if isinstance(p, dict):
        return p
    return {}


def analyze_tool_abuse(events: list[dict[str, Any]]) -> AbuseReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[AbuseDetection] = []
    profiles: list[AgentToolProfile] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_scope_violations(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_excessive_frequency(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_unauthorized_chains(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_parameter_injection(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_privilege_escalation_tools(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_shadow_tools(agent, evts_sorted, detections, det_counter)

        profile = _build_agent_profile(agent, evts_sorted, detections)
        profiles.append(profile)

    detections.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3))
    profiles.sort(key=lambda p: p.abuse_count, reverse=True)

    all_agents = sorted({d.agent_id for d in detections})
    cat_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    tools_abused: set[str] = set()

    for d in detections:
        cat_counts[d.category] += 1
        conf_counts[d.confidence] += 1
        tools_abused.add(d.tool)

    max_freq_agent = ""
    max_freq_rate = 0.0
    for p in profiles:
        if p.total_calls > 0:
            rate = p.abuse_count / p.total_calls
            if rate > max_freq_rate:
                max_freq_rate = rate
                max_freq_agent = p.agent_id

    timeline = _build_timeline(detections)

    return AbuseReport(
        detections=detections,
        agent_profiles=profiles,
        summary=AbuseSummary(
            total_detections=len(detections),
            by_category=dict(cat_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
            unique_tools_abused=len(tools_abused),
            highest_frequency_agent=max_freq_agent,
            highest_frequency_rate=round(max_freq_rate, 4),
        ),
        timeline=timeline,
    )


def _detect_scope_violations(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    declared = set()
    for ev in events:
        caps = ev.get("declared_capabilities", ev.get("capabilities", []))
        if isinstance(caps, list):
            declared.update(c.lower() for c in caps if isinstance(c, str))

    if not declared:
        return counter

    for ev in events:
        tool = _get_tool(ev)
        if not tool:
            continue
        if tool.lower() not in declared:
            counter += 1
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="scope-violation",
                confidence="medium",
                tool=tool,
                timestamp=ev.get("timestamp", ""),
                events=[ev],
                description=f"Agent '{agent}' invoked tool '{tool}' outside declared capabilities",
                mitre_technique="T1059",
            ))
    return counter


def _detect_excessive_frequency(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    tool_calls: list[dict[str, Any]] = []
    for ev in events:
        tool = _get_tool(ev)
        if tool:
            tool_calls.append(ev)

    if len(tool_calls) < 10:
        return counter

    window_size = 10
    for i in range(len(tool_calls) - window_size + 1):
        window = tool_calls[i : i + window_size]
        tools_in_window = [_get_tool(e) for e in window]
        tool_counts = defaultdict(int)
        for t in tools_in_window:
            tool_counts[t] += 1

        for tool, count in tool_counts.items():
            if count >= 8:
                counter += 1
                detections.append(AbuseDetection(
                    detection_id=f"ABUSE-{counter:03d}",
                    agent_id=agent,
                    category="excessive-frequency",
                    confidence="high" if count >= 9 else "medium",
                    tool=tool,
                    timestamp=window[0].get("timestamp", ""),
                    events=list(window),
                    description=f"Agent '{agent}' called '{tool}' {count} times in {window_size}-call window",
                    mitre_technique="T1119",
                ))
                return counter
    return counter


def _detect_unauthorized_chains(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    tool_seq: list[tuple[str, dict[str, Any]]] = []
    for ev in events:
        tool = _get_tool(ev)
        if tool:
            tool_seq.append((tool.lower(), ev))

    for i in range(len(tool_seq) - 2):
        t1, e1 = tool_seq[i]
        t2, e2 = tool_seq[i + 1]
        t3, e3 = tool_seq[i + 2]

        if _is_recon_tool(t1) and _is_privilege_tool(t2) and _is_destructive_tool(t3):
            counter += 1
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="unauthorized-chain",
                confidence="high",
                tool=f"{t1} -> {t2} -> {t3}",
                timestamp=e1.get("timestamp", ""),
                events=[e1, e2, e3],
                description=(
                    f"Agent '{agent}' executed recon->escalation->destruction chain: "
                    f"{t1} -> {t2} -> {t3}"
                ),
                mitre_technique="T1078",
            ))

        if _is_recon_tool(t1) and _is_recon_tool(t2) and _is_privilege_tool(t3):
            counter += 1
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="unauthorized-chain",
                confidence="medium",
                tool=f"{t1} -> {t2} -> {t3}",
                timestamp=e1.get("timestamp", ""),
                events=[e1, e2, e3],
                description=(
                    f"Agent '{agent}' executed recon->recon->escalation chain: "
                    f"{t1} -> {t2} -> {t3}"
                ),
                mitre_technique="T1087",
            ))

    return counter


def _detect_parameter_injection(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = _get_tool(ev)
        if not tool:
            continue
        params = _get_params(ev)
        if _has_injection(params):
            counter += 1
            injected_keys = [
                k for k, v in params.items()
                if isinstance(v, str) and INJECTION_PATTERNS.search(v)
            ]
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="parameter-injection",
                confidence="high",
                tool=tool,
                timestamp=ev.get("timestamp", ""),
                events=[ev],
                description=(
                    f"Agent '{agent}' passed injection payload in '{tool}' "
                    f"parameters: {', '.join(injected_keys)}"
                ),
                mitre_technique="T1059.004",
            ))
    return counter


def _detect_privilege_escalation_tools(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = _get_tool(ev)
        if not tool:
            continue
        if _is_privilege_tool(tool):
            counter += 1
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="privilege-escalation-tool",
                confidence="medium",
                tool=tool,
                timestamp=ev.get("timestamp", ""),
                events=[ev],
                description=f"Agent '{agent}' invoked privilege escalation tool '{tool}'",
                mitre_technique="T1548",
            ))
    return counter


def _detect_shadow_tools(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    for ev in events:
        claimed = ev.get("claimed_tool", "")
        actual = ev.get("actual_tool", "")
        if claimed and actual and claimed != actual:
            counter += 1
            detections.append(AbuseDetection(
                detection_id=f"ABUSE-{counter:03d}",
                agent_id=agent,
                category="shadow-tool",
                confidence="high",
                tool=f"{claimed} (actual: {actual})",
                timestamp=ev.get("timestamp", ""),
                events=[ev],
                description=(
                    f"Agent '{agent}' claimed tool '{claimed}' but actually executed '{actual}'"
                ),
                mitre_technique="T1036",
            ))
    return counter


def _build_agent_profile(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
) -> AgentToolProfile:
    tool_counts: dict[str, int] = defaultdict(int)
    declared: set[str] = set()
    undeclared = 0

    for ev in events:
        caps = ev.get("declared_capabilities", ev.get("capabilities", []))
        if isinstance(caps, list):
            declared.update(c for c in caps if isinstance(c, str))

    for ev in events:
        tool = _get_tool(ev)
        if tool:
            tool_counts[tool] += 1
            if declared and tool.lower() not in {d.lower() for d in declared}:
                undeclared += 1

    top = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    agent_det_count = sum(1 for d in detections if d.agent_id == agent)

    return AgentToolProfile(
        agent_id=agent,
        total_calls=sum(tool_counts.values()),
        unique_tools=len(tool_counts),
        abuse_count=agent_det_count,
        top_tools=top,
        declared_tools=sorted(declared),
        undeclared_calls=undeclared,
    )


def _build_timeline(detections: list[AbuseDetection]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in detections:
        entries.append({
            "timestamp": d.timestamp,
            "detection_id": d.detection_id,
            "agent_id": d.agent_id,
            "category": d.category,
            "confidence": d.confidence,
            "tool": d.tool,
        })
    entries.sort(key=lambda e: e.get("timestamp", ""))
    return entries


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


def format_text(report: AbuseReport) -> str:
    lines: list[str] = []
    lines.append("Tool Abuse Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Unique tools abused:    {s.unique_tools_abused}")
    if s.highest_frequency_agent:
        lines.append(f"  Highest abuse rate:     {s.highest_frequency_agent} ({s.highest_frequency_rate:.2%})")
    lines.append("")

    if s.by_category:
        lines.append("  By Category:")
        for cat, count in sorted(s.by_category.items()):
            desc = ABUSE_CATEGORIES.get(cat, cat)
            lines.append(f"    {cat}: {count} ({desc})")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.confidence.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Category: {d.category}")
        lines.append(f"    Tool: {d.tool}")
        lines.append(f"    {d.description}")
        if d.mitre_technique:
            lines.append(f"    MITRE: {d.mitre_technique}")
        lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    if report.agent_profiles:
        lines.append("  Agent Tool Profiles:")
        for p in report.agent_profiles[:10]:
            lines.append(f"    {p.agent_id}: {p.total_calls} calls, {p.unique_tools} tools, {p.abuse_count} abuses")
            if p.undeclared_calls:
                lines.append(f"      Undeclared calls: {p.undeclared_calls}")
            if p.top_tools:
                top_str = ", ".join(f"{t}({c})" for t, c in p.top_tools[:3])
                lines.append(f"      Top tools: {top_str}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AbuseReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "agent_profiles": [
            {
                "agent_id": p.agent_id,
                "total_calls": p.total_calls,
                "unique_tools": p.unique_tools,
                "abuse_count": p.abuse_count,
                "top_tools": [{"tool": t, "count": c} for t, c in p.top_tools],
                "declared_tools": p.declared_tools,
                "undeclared_calls": p.undeclared_calls,
            }
            for p in report.agent_profiles
        ],
        "summary": asdict(report.summary),
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
