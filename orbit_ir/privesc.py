"""Privilege escalation path detection for agent evidence.

Analyzes control-plane and transcript evidence to detect patterns
where agents gain or exercise capabilities beyond their initial
scope—role escalation, credential theft, resource boundary violations,
and self-modification of access controls.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SENSITIVE_RESOURCES = {
    "iam", "rbac", "policy", "role", "permission", "secret",
    "credential", "token", "key", "cert", "admin", "root",
    "sudo", "passwd", "shadow", "auth", "acl", "privilege",
}

SENSITIVE_EFFECTS = {
    "role-modified", "policy-modified", "credential-created",
    "credential-rotated", "permission-granted", "admin-access",
    "privilege-escalated", "access-control-modified",
    "secret-read", "secret-written", "token-minted",
}

ESCALATION_TOOLS = {
    "create_role", "modify_role", "assign_role", "grant_permission",
    "create_credential", "rotate_credential", "create_token",
    "modify_policy", "update_iam", "assume_role", "elevate",
    "create_admin", "modify_acl", "set_permission",
}


@dataclass
class EscalationStep:
    timestamp: str
    agent_id: str
    tool_call_id: str
    action: str
    resource: str
    effect: str
    credential_id: str
    source_file: str
    line: int
    reason: str


@dataclass
class EscalationPath:
    path_id: str
    agent_id: str
    steps: list[EscalationStep] = field(default_factory=list)
    severity: str = "medium"
    description: str = ""
    initial_role: str = ""
    final_role: str = ""
    credentials_used: list[str] = field(default_factory=list)
    resources_touched: list[str] = field(default_factory=list)


@dataclass
class PrivescReport:
    paths: list[EscalationPath]
    summary: PrivescSummary
    agents_involved: list[str]
    credential_chains: list[dict[str, Any]]


@dataclass
class PrivescSummary:
    total_paths: int
    critical_paths: int
    high_paths: int
    agents_escalating: int
    unique_credentials: int
    sensitive_resources_accessed: int
    by_severity: dict[str, int] = field(default_factory=dict)


def _is_sensitive_resource(resource: str) -> bool:
    lower = resource.lower()
    return any(s in lower for s in SENSITIVE_RESOURCES)


def _is_sensitive_effect(effect: str) -> bool:
    lower = effect.lower()
    return lower in SENSITIVE_EFFECTS or any(s in lower for s in SENSITIVE_RESOURCES)


def _is_escalation_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in ESCALATION_TOOLS or any(s in lower for s in {"role", "permission", "credential", "privilege", "admin", "iam"})


def _classify_step_reason(tool: str, resource: str, effect: str, policy_decision: str) -> str | None:
    if policy_decision in ("denied", "blocked") and effect not in ("", "none"):
        return "bypassed-policy-denial"
    if _is_escalation_tool(tool):
        return "privilege-tool-invoked"
    if _is_sensitive_effect(effect):
        return "sensitive-effect-observed"
    if _is_sensitive_resource(resource):
        return "sensitive-resource-accessed"
    return None


def analyze_privilege_escalation(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> PrivescReport:
    if control_events is None:
        control_events = []

    agent_actions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    agent_credentials: dict[str, list[str]] = defaultdict(list)
    agent_roles: dict[str, list[str]] = defaultdict(list)
    sensitive_steps: list[EscalationStep] = []

    for i, ev in enumerate(control_events):
        agent = ev.get("agent_id", "")
        tool = ev.get("actual_tool", "")
        resource = ev.get("resource", "")
        effect = ev.get("effect", "")
        cred = ev.get("credential_id", "")
        policy = ev.get("policy_decision", "")
        ts = ev.get("timestamp", "")
        tcid = ev.get("tool_call_id", "")

        agent_actions[agent].append(ev)
        if cred and cred not in agent_credentials[agent]:
            agent_credentials[agent].append(cred)

        role = ev.get("role", "")
        if role and role not in agent_roles[agent]:
            agent_roles[agent].append(role)

        reason = _classify_step_reason(tool, resource, effect, policy)
        if reason:
            sensitive_steps.append(EscalationStep(
                timestamp=ts,
                agent_id=agent,
                tool_call_id=tcid,
                action=tool,
                resource=resource,
                effect=effect,
                credential_id=cred,
                source_file="control_plane.jsonl",
                line=i + 1,
                reason=reason,
            ))

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        tool = ev.get("claimed_tool", ev.get("tool", ""))
        resource = ev.get("resource", "")
        effect = ev.get("effect", "")
        cred = ev.get("credential_id", "")
        policy = ev.get("policy_decision", "")
        ts = ev.get("timestamp", "")
        tcid = ev.get("tool_call_id", ev.get("event_id", ""))

        reason = _classify_step_reason(tool, resource, effect, policy)
        if reason and not any(
            s.tool_call_id == tcid and s.agent_id == agent
            for s in sensitive_steps
        ):
            sensitive_steps.append(EscalationStep(
                timestamp=ts,
                agent_id=agent,
                tool_call_id=tcid,
                action=tool,
                resource=resource,
                effect=effect,
                credential_id=cred,
                source_file="transcripts.jsonl",
                line=i + 1,
                reason=reason,
            ))

    sensitive_steps.sort(key=lambda s: s.timestamp)

    paths = _build_paths(sensitive_steps, agent_credentials, agent_roles)
    cred_chains = _build_credential_chains(sensitive_steps)

    all_agents = sorted({p.agent_id for p in paths})
    all_creds = set()
    all_resources = set()
    for p in paths:
        all_creds.update(p.credentials_used)
        all_resources.update(p.resources_touched)

    sev_counts: dict[str, int] = defaultdict(int)
    for p in paths:
        sev_counts[p.severity] += 1

    return PrivescReport(
        paths=paths,
        summary=PrivescSummary(
            total_paths=len(paths),
            critical_paths=sev_counts.get("critical", 0),
            high_paths=sev_counts.get("high", 0),
            agents_escalating=len(all_agents),
            unique_credentials=len(all_creds),
            sensitive_resources_accessed=len(all_resources),
            by_severity=dict(sev_counts),
        ),
        agents_involved=all_agents,
        credential_chains=cred_chains,
    )


def _build_paths(
    steps: list[EscalationStep],
    agent_creds: dict[str, list[str]],
    agent_roles: dict[str, list[str]],
) -> list[EscalationPath]:
    by_agent: dict[str, list[EscalationStep]] = defaultdict(list)
    for s in steps:
        by_agent[s.agent_id].append(s)

    paths: list[EscalationPath] = []
    for agent, agent_steps in sorted(by_agent.items()):
        if not agent_steps:
            continue

        creds = sorted(set(s.credential_id for s in agent_steps if s.credential_id))
        resources = sorted(set(s.resource for s in agent_steps if s.resource))

        severity = _path_severity(agent_steps)

        roles = agent_roles.get(agent, [])
        initial = roles[0] if roles else ""
        final = roles[-1] if len(roles) > 1 else initial

        desc = _path_description(agent, agent_steps, initial, final)

        paths.append(EscalationPath(
            path_id=f"PE-{len(paths)+1:03d}",
            agent_id=agent,
            steps=agent_steps,
            severity=severity,
            description=desc,
            initial_role=initial,
            final_role=final,
            credentials_used=creds,
            resources_touched=resources,
        ))

    paths.sort(key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p.severity, 4))
    return paths


def _path_severity(steps: list[EscalationStep]) -> str:
    reasons = {s.reason for s in steps}
    if "bypassed-policy-denial" in reasons:
        return "critical"
    has_priv_tool = "privilege-tool-invoked" in reasons
    has_sensitive_effect = "sensitive-effect-observed" in reasons
    if has_priv_tool and not has_sensitive_effect and len(steps) >= 2:
        for s in steps:
            if s.reason == "privilege-tool-invoked" and _is_sensitive_effect(s.effect):
                has_sensitive_effect = True
                break
    if has_priv_tool and has_sensitive_effect:
        return "critical"
    if has_priv_tool:
        return "high"
    if "sensitive-effect-observed" in reasons:
        return "high"
    if len(steps) >= 3:
        return "high"
    if "sensitive-resource-accessed" in reasons:
        return "medium"
    return "low"


def _path_description(
    agent: str,
    steps: list[EscalationStep],
    initial_role: str,
    final_role: str,
) -> str:
    reasons = {s.reason for s in steps}
    parts: list[str] = [f"Agent '{agent}' performed {len(steps)} escalation-relevant action(s)"]
    if "bypassed-policy-denial" in reasons:
        parts.append("including bypassing a policy denial")
    if "privilege-tool-invoked" in reasons:
        tools = sorted(set(s.action for s in steps if s.reason == "privilege-tool-invoked"))
        parts.append(f"using privilege tools: {', '.join(tools)}")
    if initial_role and final_role and initial_role != final_role:
        parts.append(f"role changed from '{initial_role}' to '{final_role}'")
    return "; ".join(parts)


def _build_credential_chains(steps: list[EscalationStep]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    cred_usage: dict[str, list[EscalationStep]] = defaultdict(list)
    for s in steps:
        if s.credential_id:
            cred_usage[s.credential_id].append(s)

    for cred, cred_steps in sorted(cred_usage.items()):
        agents = sorted(set(s.agent_id for s in cred_steps))
        if len(agents) > 1 or len(cred_steps) > 1:
            chains.append({
                "credential_id": cred,
                "agents": agents,
                "usage_count": len(cred_steps),
                "shared": len(agents) > 1,
                "actions": [
                    {"agent": s.agent_id, "tool": s.action, "resource": s.resource, "timestamp": s.timestamp}
                    for s in cred_steps
                ],
            })

    return chains


def format_text(report: PrivescReport) -> str:
    lines: list[str] = []
    lines.append("Privilege Escalation Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Escalation paths:       {s.total_paths}")
    lines.append(f"  Critical paths:         {s.critical_paths}")
    lines.append(f"  High severity paths:    {s.high_paths}")
    lines.append(f"  Agents escalating:      {s.agents_escalating}")
    lines.append(f"  Unique credentials:     {s.unique_credentials}")
    lines.append(f"  Sensitive resources:    {s.sensitive_resources_accessed}")
    lines.append("")

    if report.paths:
        for p in report.paths:
            lines.append(f"  [{p.severity.upper()}] {p.path_id}: {p.agent_id}")
            lines.append(f"    {p.description}")
            if p.initial_role and p.final_role and p.initial_role != p.final_role:
                lines.append(f"    Role: {p.initial_role} -> {p.final_role}")
            if p.credentials_used:
                lines.append(f"    Credentials: {', '.join(p.credentials_used)}")
            if p.resources_touched:
                lines.append(f"    Resources: {', '.join(p.resources_touched[:5])}")
                if len(p.resources_touched) > 5:
                    lines.append(f"    ... and {len(p.resources_touched) - 5} more")
            lines.append(f"    Steps: {len(p.steps)}")
            for step in p.steps:
                lines.append(f"      - {step.timestamp}: {step.action} on {step.resource} [{step.reason}]")
            lines.append("")

    if report.credential_chains:
        lines.append("  Credential Chains:")
        lines.append("  " + "-" * 60)
        for chain in report.credential_chains:
            shared = " (SHARED)" if chain["shared"] else ""
            lines.append(f"    {chain['credential_id']}{shared}: {chain['usage_count']} uses by {', '.join(chain['agents'])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: PrivescReport) -> str:
    data = {
        "paths": [
            {
                **{k: v for k, v in asdict(p).items() if k != "steps"},
                "steps": [asdict(s) for s in p.steps],
            }
            for p in report.paths
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "credential_chains": report.credential_chains,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
