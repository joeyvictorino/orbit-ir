"""Agent role drift detection from observed behavior vs. declared roles.

Compares each agent's actual actions (tools used, resources accessed, action
types) against its declared or expected role to detect when agents operate
outside their intended scope.  Role definitions come from evidence metadata
(role fields) or from a baseline expectation map.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ROLE_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "recon": {
        "allowed_actions": {"read", "search", "list", "query", "fetch", "scan", "enumerate"},
        "forbidden_actions": {"write", "delete", "execute", "deploy", "create_user", "grant_access"},
        "max_risk": "low",
    },
    "probe": {
        "allowed_actions": {"read", "write", "execute", "http_request", "scan", "test"},
        "forbidden_actions": {"delete", "deploy", "create_user", "grant_access"},
        "max_risk": "medium",
    },
    "validate": {
        "allowed_actions": {"read", "execute", "verify", "check", "test", "compare"},
        "forbidden_actions": {"delete", "deploy", "create_user", "grant_access", "write"},
        "max_risk": "medium",
    },
    "remediate": {
        "allowed_actions": {"read", "write", "patch", "fix", "update", "modify"},
        "forbidden_actions": {"delete", "deploy", "create_user", "grant_access"},
        "max_risk": "medium",
    },
    "admin": {
        "allowed_actions": {"read", "write", "delete", "execute", "deploy", "create_user", "grant_access"},
        "forbidden_actions": set(),
        "max_risk": "critical",
    },
    "monitor": {
        "allowed_actions": {"read", "list", "query", "watch", "subscribe", "poll"},
        "forbidden_actions": {"write", "delete", "execute", "deploy", "create_user", "grant_access"},
        "max_risk": "low",
    },
}

RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class DriftViolation:
    action: str
    tool: str
    resource: str
    reason: str
    risk_delta: int


@dataclass
class AgentRoleDrift:
    agent_id: str
    declared_role: str
    inferred_role: str
    total_actions: int = 0
    compliant_actions: int = 0
    violating_actions: int = 0
    drift_score: float = 0.0
    violations: list[DriftViolation] = field(default_factory=list)


@dataclass
class RoleDriftSummary:
    total_agents: int = 0
    agents_with_drift: int = 0
    total_violations: int = 0
    avg_drift_score: float = 0.0
    max_drift_score: float = 0.0
    highest_drift_agent: str = ""


@dataclass
class RoleDriftReport:
    agents: list[AgentRoleDrift] = field(default_factory=list)
    summary: RoleDriftSummary = field(default_factory=RoleDriftSummary)


def _extract_action(ev: dict[str, Any]) -> str:
    action = ev.get("action", "")
    if action:
        return action.lower()
    tool = ev.get("tool", ev.get("tool_name", ""))
    if tool:
        lower = tool.lower()
        for keyword in ("delete", "remove", "drop", "purge"):
            if keyword in lower:
                return "delete"
        for keyword in ("write", "create", "put", "post", "modify", "update", "patch"):
            if keyword in lower:
                return "write"
        for keyword in ("execute", "run", "bash", "exec", "invoke"):
            if keyword in lower:
                return "execute"
        for keyword in ("deploy", "publish", "release", "push", "upload"):
            if keyword in lower:
                return "deploy"
        for keyword in ("grant_access", "elevate", "sudo", "chmod"):
            if keyword in lower:
                return "grant_access"
        for keyword in ("create_user",):
            if keyword in lower:
                return "create_user"
        for keyword in ("read", "get", "list", "search", "query", "fetch", "view", "cat"):
            if keyword in lower:
                return "read"
    return "unknown"


def _infer_role(actions: dict[str, int]) -> str:
    has_write = actions.get("write", 0) > 0
    has_delete = actions.get("delete", 0) > 0
    has_execute = actions.get("execute", 0) > 0
    has_deploy = actions.get("deploy", 0) > 0
    has_admin = actions.get("create_user", 0) > 0 or actions.get("grant_access", 0) > 0

    if has_admin:
        return "admin"
    if has_deploy:
        return "admin"
    if has_delete and has_write:
        return "admin"
    if has_execute and has_write:
        return "probe"
    if has_write:
        return "remediate"
    if has_execute:
        return "validate"
    return "recon"


def analyze_role_drift(events: list[dict[str, Any]], role_map: dict[str, str] | None = None) -> RoleDriftReport:
    if role_map is None:
        role_map = {}

    agent_events: dict[str, list[dict]] = defaultdict(list)
    agent_roles: dict[str, str] = {}

    for ev in events:
        agent_id = ev.get("agent_id") or ev.get("agent") or ev.get("identity", "unknown")
        agent_events[agent_id].append(ev)

        if agent_id not in agent_roles:
            role = ev.get("role", ev.get("agent_role", ""))
            if role:
                agent_roles[agent_id] = role.lower()

    for aid, role in role_map.items():
        agent_roles[aid] = role.lower()

    agents: list[AgentRoleDrift] = []
    for agent_id in sorted(agent_events.keys()):
        evs = agent_events[agent_id]
        declared = agent_roles.get(agent_id, "")
        actions: dict[str, int] = defaultdict(int)
        action_details: list[tuple[str, str, str]] = []

        for ev in evs:
            act = _extract_action(ev)
            if act != "unknown":
                actions[act] += 1
                tool = ev.get("tool", ev.get("tool_name", ""))
                resource = ev.get("resource", ev.get("target", ev.get("path", "")))
                action_details.append((act, tool, resource))

        inferred = _infer_role(actions)
        total = sum(actions.values())

        if not declared:
            declared = inferred

        expectations = ROLE_EXPECTATIONS.get(declared, ROLE_EXPECTATIONS.get("recon", {}))
        allowed = expectations.get("allowed_actions", set())
        forbidden = expectations.get("forbidden_actions", set())
        max_risk_str = expectations.get("max_risk", "low")
        max_risk = RISK_LEVELS.get(max_risk_str, 0)

        violations: list[DriftViolation] = []
        compliant = 0

        for act, tool, resource in action_details:
            if act in forbidden:
                risk_delta = _action_risk(act) - max_risk
                violations.append(DriftViolation(
                    action=act,
                    tool=tool,
                    resource=resource,
                    reason=f"forbidden action '{act}' for role '{declared}'",
                    risk_delta=max(risk_delta, 0),
                ))
            elif act not in allowed and allowed:
                violations.append(DriftViolation(
                    action=act,
                    tool=tool,
                    resource=resource,
                    reason=f"unexpected action '{act}' for role '{declared}'",
                    risk_delta=0,
                ))
            else:
                compliant += 1

        drift_score = len(violations) / max(total, 1)

        agents.append(AgentRoleDrift(
            agent_id=agent_id,
            declared_role=declared,
            inferred_role=inferred,
            total_actions=total,
            compliant_actions=compliant,
            violating_actions=len(violations),
            drift_score=round(drift_score, 4),
            violations=violations,
        ))

    agents.sort(key=lambda a: a.drift_score, reverse=True)
    summary = _build_summary(agents)
    return RoleDriftReport(agents=agents, summary=summary)


def _action_risk(action: str) -> int:
    risks = {
        "read": 0, "search": 0, "list": 0, "query": 0, "fetch": 0,
        "write": 1, "create": 1, "update": 1, "modify": 1, "patch": 1,
        "execute": 2, "delete": 2, "deploy": 3,
        "create_user": 3, "grant_access": 3,
    }
    return risks.get(action, 0)


def _build_summary(agents: list[AgentRoleDrift]) -> RoleDriftSummary:
    if not agents:
        return RoleDriftSummary()
    drifted = [a for a in agents if a.drift_score > 0]
    scores = [a.drift_score for a in agents]
    max_score = max(scores) if scores else 0.0
    highest = next((a.agent_id for a in agents if a.drift_score == max_score), "")
    total_violations = sum(a.violating_actions for a in agents)
    return RoleDriftSummary(
        total_agents=len(agents),
        agents_with_drift=len(drifted),
        total_violations=total_violations,
        avg_drift_score=round(sum(scores) / len(scores), 4),
        max_drift_score=max_score,
        highest_drift_agent=highest,
    )


def format_text(report: RoleDriftReport) -> str:
    lines = [f"Role Drift Analysis ({report.summary.total_agents} agents)\n"]

    s = report.summary
    if s.agents_with_drift:
        lines.append(f"  Agents with drift: {s.agents_with_drift}/{s.total_agents}")
        lines.append(f"  Total violations: {s.total_violations}")
    lines.append(f"  Average drift score: {s.avg_drift_score:.2f}")
    if s.highest_drift_agent:
        lines.append(f"  Highest drift: {s.highest_drift_agent} ({s.max_drift_score:.2f})")
    lines.append("")

    for a in report.agents:
        flag = " [DRIFTED]" if a.drift_score > 0 else ""
        role_info = f"declared={a.declared_role}"
        if a.inferred_role != a.declared_role:
            role_info += f", inferred={a.inferred_role}"
        lines.append(f"  {a.agent_id}: drift={a.drift_score:.2f}, {role_info}{flag}")
        lines.append(f"    Actions: {a.total_actions} total, {a.compliant_actions} compliant, {a.violating_actions} violations")

        for v in a.violations[:10]:
            tool_str = f" via {v.tool}" if v.tool else ""
            res_str = f" on {v.resource}" if v.resource else ""
            lines.append(f"    - {v.reason}{tool_str}{res_str}")
        if len(a.violations) > 10:
            lines.append(f"    ... and {len(a.violations) - 10} more violations")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: RoleDriftReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(evidence_dir: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(evidence_dir)
    for f in sorted(p.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return events
