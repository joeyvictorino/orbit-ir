"""Privilege abuse pattern detection for agent evidence.

Analyzes agent events to detect patterns where agents abuse legitimately
granted privileges—scope creep, opportunity abuse, authority bypass,
and accessing resources outside stated purpose.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ABUSE_TYPES = {
    "scope-creep": "Gradually expanding access use beyond original purpose",
    "opportunity-abuse": "Using permissions for unintended purposes",
    "authority-bypass": "Acting beyond assigned role boundaries",
}

ADMIN_TOOLS = {
    "create_role", "modify_role", "delete_role", "assign_role",
    "grant_permission", "revoke_permission", "modify_policy",
    "create_user", "delete_user", "modify_acl", "update_iam",
    "create_admin", "elevate", "assume_role",
}

NON_ADMIN_TASKS = {
    "read_file", "write_file", "list_directory", "search_files",
    "read_database", "query_db", "send_message", "log_event",
}

ROLE_HIERARCHY = {
    "viewer": 0, "reader": 0,
    "editor": 1, "writer": 1,
    "operator": 2, "developer": 2,
    "admin": 3, "administrator": 3,
    "root": 4, "superadmin": 4,
}


@dataclass
class AbuseDetection:
    detection_id: str
    agent_id: str
    abuse_type: str
    severity: str
    confidence: str
    timestamp: str
    tool: str
    resource: str
    expected_scope: str
    actual_action: str
    description: str


@dataclass
class AbusePattern:
    pattern_type: str
    agent_id: str
    occurrences: int
    first_seen: str
    last_seen: str
    description: str


@dataclass
class AgentAbuseScore:
    agent_id: str
    total_detections: int
    by_type: dict[str, int]
    risk_score: float


@dataclass
class PrivilegeAbuseSummary:
    total_detections: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int


@dataclass
class PrivilegeAbuseReport:
    detections: list[AbuseDetection]
    abuse_patterns: list[AbusePattern]
    agent_scores: list[AgentAbuseScore]
    summary: PrivilegeAbuseSummary


def _get_role_level(role: str) -> int:
    return ROLE_HIERARCHY.get(role.lower(), -1)


def _is_admin_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in ADMIN_TOOLS or any(
        k in lower for k in {"admin", "privilege", "permission", "policy", "iam"}
    )


def _severity_for_abuse(abuse_type: str, role_level: int, tool: str) -> str:
    if abuse_type == "authority-bypass":
        return "critical" if role_level >= 3 else "high"
    if abuse_type == "scope-creep" and _is_admin_tool(tool):
        return "high"
    if abuse_type == "opportunity-abuse":
        return "high" if _is_admin_tool(tool) else "medium"
    return "medium"


def analyze_privilege_abuse(events: list[dict[str, Any]]) -> PrivilegeAbuseReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    agent_roles: dict[str, str] = {}
    agent_scopes: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        agent_events[agent].append(ev)

        role = ev.get("role", "")
        if role:
            agent_roles[agent] = role

        scope = ev.get("scope", ev.get("purpose", ""))
        if scope:
            agent_scopes[agent].add(scope)

    detections: list[AbuseDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        role = agent_roles.get(agent, "")
        scopes = agent_scopes.get(agent, set())

        det_counter = _detect_admin_for_non_admin(
            agent, evts_sorted, role, detections, det_counter
        )
        det_counter = _detect_out_of_scope(
            agent, evts_sorted, scopes, detections, det_counter
        )
        det_counter = _detect_authority_bypass(
            agent, evts_sorted, role, detections, det_counter
        )
        det_counter = _detect_cross_agent_access(
            agent, evts_sorted, detections, det_counter
        )

    detections.sort(
        key=lambda d: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            d.severity, 4
        )
    )

    patterns = _build_patterns(detections)
    scores = _build_agent_scores(detections)

    type_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    for d in detections:
        type_counts[d.abuse_type] += 1
        sev_counts[d.severity] += 1
        conf_counts[d.confidence] += 1

    return PrivilegeAbuseReport(
        detections=detections,
        abuse_patterns=patterns,
        agent_scores=scores,
        summary=PrivilegeAbuseSummary(
            total_detections=len(detections),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len({d.agent_id for d in detections}),
        ),
    )


def _detect_admin_for_non_admin(
    agent: str,
    events: list[dict[str, Any]],
    role: str,
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    role_level = _get_role_level(role) if role else -1
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", "")
        purpose = ev.get("purpose", ev.get("task", ""))

        if _is_admin_tool(tool) and purpose:
            purpose_lower = purpose.lower()
            is_routine = any(
                k in purpose_lower
                for k in {"read", "query", "list", "check", "view", "monitor"}
            )
            if is_routine:
                counter += 1
                sev = _severity_for_abuse("opportunity-abuse", role_level, tool)
                detections.append(
                    AbuseDetection(
                        detection_id=f"ABUSE-{counter:03d}",
                        agent_id=agent,
                        abuse_type="opportunity-abuse",
                        severity=sev,
                        confidence="medium",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=resource,
                        expected_scope=purpose,
                        actual_action=f"Used admin tool '{tool}' for routine task '{purpose}'",
                        description=f"Agent '{agent}' used privileged tool '{tool}' for routine task: {purpose}",
                    )
                )
    return counter


def _detect_out_of_scope(
    agent: str,
    events: list[dict[str, Any]],
    scopes: set[str],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    if not scopes:
        return counter

    scope_keywords = set()
    for s in scopes:
        scope_keywords.update(w.lower() for w in s.split() if len(w) > 2)

    accessed_resources: list[str] = []
    for ev in events:
        resource = ev.get("resource", "")
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not resource:
            continue

        resource_lower = resource.lower()
        in_scope = any(kw in resource_lower for kw in scope_keywords) if scope_keywords else True

        if not in_scope:
            accessed_resources.append(resource)
            if len(accessed_resources) >= 3:
                counter += 1
                detections.append(
                    AbuseDetection(
                        detection_id=f"ABUSE-{counter:03d}",
                        agent_id=agent,
                        abuse_type="scope-creep",
                        severity=_severity_for_abuse("scope-creep", -1, tool),
                        confidence="medium" if len(accessed_resources) >= 5 else "low",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=resource,
                        expected_scope=", ".join(sorted(scopes)),
                        actual_action=f"Accessed {len(accessed_resources)} out-of-scope resources",
                        description=(
                            f"Agent '{agent}' accessed {len(accessed_resources)} resources "
                            f"outside declared scope ({', '.join(sorted(scopes))})"
                        ),
                    )
                )
                accessed_resources = []
    return counter


def _detect_authority_bypass(
    agent: str,
    events: list[dict[str, Any]],
    role: str,
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    role_level = _get_role_level(role) if role else -1
    if role_level < 0:
        return counter

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", "")
        target_role = ev.get("target_role", "")

        if target_role:
            target_level = _get_role_level(target_role)
            if target_level > role_level:
                counter += 1
                detections.append(
                    AbuseDetection(
                        detection_id=f"ABUSE-{counter:03d}",
                        agent_id=agent,
                        abuse_type="authority-bypass",
                        severity=_severity_for_abuse("authority-bypass", target_level, tool),
                        confidence="high",
                        timestamp=ev.get("timestamp", ""),
                        tool=tool,
                        resource=resource,
                        expected_scope=f"role={role} (level {role_level})",
                        actual_action=f"Targeted role '{target_role}' (level {target_level})",
                        description=(
                            f"Agent '{agent}' (role '{role}') attempted to access/modify "
                            f"role '{target_role}' which exceeds its authority"
                        ),
                    )
                )

        if _is_admin_tool(tool) and role_level < 2:
            counter += 1
            detections.append(
                AbuseDetection(
                    detection_id=f"ABUSE-{counter:03d}",
                    agent_id=agent,
                    abuse_type="authority-bypass",
                    severity="high",
                    confidence="high",
                    timestamp=ev.get("timestamp", ""),
                    tool=tool,
                    resource=resource,
                    expected_scope=f"role={role} (level {role_level})",
                    actual_action=f"Used admin tool '{tool}' with non-admin role",
                    description=(
                        f"Agent '{agent}' (role '{role}') used admin tool '{tool}' "
                        f"without admin-level role"
                    ),
                )
            )
    return counter


def _detect_cross_agent_access(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[AbuseDetection],
    counter: int,
) -> int:
    for ev in events:
        resource = ev.get("resource", "")
        resource_owner = ev.get("resource_owner", "")
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        delegated = ev.get("delegated", False)

        if resource_owner and resource_owner != agent and not delegated:
            counter += 1
            detections.append(
                AbuseDetection(
                    detection_id=f"ABUSE-{counter:03d}",
                    agent_id=agent,
                    abuse_type="opportunity-abuse",
                    severity="high",
                    confidence="high",
                    timestamp=ev.get("timestamp", ""),
                    tool=tool,
                    resource=resource,
                    expected_scope=f"own resources (agent={agent})",
                    actual_action=f"Accessed resource owned by '{resource_owner}' without delegation",
                    description=(
                        f"Agent '{agent}' accessed resource '{resource}' owned by "
                        f"'{resource_owner}' without delegation"
                    ),
                )
            )
    return counter


def _build_patterns(detections: list[AbuseDetection]) -> list[AbusePattern]:
    by_agent_type: dict[tuple[str, str], list[AbuseDetection]] = defaultdict(list)
    for d in detections:
        by_agent_type[(d.agent_id, d.abuse_type)].append(d)

    patterns: list[AbusePattern] = []
    for (agent, abuse_type), dets in sorted(by_agent_type.items()):
        if len(dets) < 2:
            continue
        timestamps = sorted(d.timestamp for d in dets if d.timestamp)
        patterns.append(
            AbusePattern(
                pattern_type=abuse_type,
                agent_id=agent,
                occurrences=len(dets),
                first_seen=timestamps[0] if timestamps else "",
                last_seen=timestamps[-1] if timestamps else "",
                description=(
                    f"Agent '{agent}' showed repeated {abuse_type} pattern "
                    f"({len(dets)} occurrences)"
                ),
            )
        )
    return patterns


def _build_agent_scores(detections: list[AbuseDetection]) -> list[AgentAbuseScore]:
    by_agent: dict[str, list[AbuseDetection]] = defaultdict(list)
    for d in detections:
        by_agent[d.agent_id].append(d)

    scores: list[AgentAbuseScore] = []
    for agent, dets in sorted(by_agent.items()):
        type_counts: dict[str, int] = defaultdict(int)
        for d in dets:
            type_counts[d.abuse_type] += 1

        sev_weights = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
        total_weight = sum(sev_weights.get(d.severity, 1.0) for d in dets)
        risk = min(total_weight / 10.0, 1.0)

        scores.append(
            AgentAbuseScore(
                agent_id=agent,
                total_detections=len(dets),
                by_type=dict(type_counts),
                risk_score=round(risk, 2),
            )
        )

    scores.sort(key=lambda s: s.risk_score, reverse=True)
    return scores


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


def format_text(report: PrivilegeAbuseReport) -> str:
    lines: list[str] = []
    lines.append("Privilege Abuse Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if s.by_type:
        lines.append("  By Abuse Type:")
        for t, c in sorted(s.by_type.items()):
            desc = ABUSE_TYPES.get(t, t)
            lines.append(f"    {t}: {c} ({desc})")
        lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sv, c in sorted(s.by_severity.items()):
            lines.append(f"    {sv}: {c}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.severity.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Type: {d.abuse_type}")
        lines.append(f"    {d.description}")
        lines.append(f"    Expected scope: {d.expected_scope}")
        lines.append(f"    Actual action: {d.actual_action}")
        lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    if report.abuse_patterns:
        lines.append("  Repeated Patterns:")
        lines.append("  " + "-" * 60)
        for p in report.abuse_patterns:
            lines.append(f"    {p.agent_id}: {p.pattern_type} x{p.occurrences}")
            lines.append(f"      {p.description}")
        lines.append("")

    if report.agent_scores:
        lines.append("  Agent Risk Scores:")
        lines.append("  " + "-" * 60)
        for sc in report.agent_scores:
            lines.append(f"    {sc.agent_id}: risk={sc.risk_score:.2f} ({sc.total_detections} detections)")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: PrivilegeAbuseReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "abuse_patterns": [asdict(p) for p in report.abuse_patterns],
        "agent_scores": [asdict(s) for s in report.agent_scores],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
