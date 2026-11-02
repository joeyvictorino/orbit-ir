"""Privilege chain reconstruction from agent evidence.

Reconstructs the complete path from initial access to final privilege
level, linking credentials, role changes, and escalation steps into
coherent chains with critical-link and bypass-point identification.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ESCALATION_ACTIONS = {
    "assume_role", "create_role", "modify_role", "assign_role",
    "grant_permission", "elevate", "create_credential", "create_token",
    "modify_policy", "update_iam", "modify_acl", "set_permission",
    "rotate_credential", "create_admin",
}

PRIVILEGE_LEVELS = {
    "none": 0, "guest": 1, "viewer": 2, "user": 3,
    "editor": 4, "operator": 5, "admin": 6, "root": 7,
    "superadmin": 8,
}


@dataclass
class ChainLink:
    """A single step in a privilege escalation chain."""
    timestamp: str
    agent_id: str
    action: str
    resource: str
    effect: str
    credential_id: str
    source_role: str
    target_role: str
    is_bypass: bool
    policy_decision: str


@dataclass
class PrivilegeChain:
    """A complete privilege escalation chain for one agent."""
    chain_id: str
    agent_id: str
    links: list[ChainLink] = field(default_factory=list)
    initial_privilege: str = "none"
    final_privilege: str = "none"
    chain_length: int = 0
    bypass_count: int = 0
    critical_links: list[int] = field(default_factory=list)
    credentials_used: list[str] = field(default_factory=list)
    severity: str = "low"


@dataclass
class ChainSummary:
    total_chains: int
    critical_chains: int
    high_chains: int
    total_links: int
    total_bypasses: int
    agents_involved: int
    max_chain_length: int
    avg_chain_length: float
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class ChainReport:
    chains: list[PrivilegeChain]
    summary: ChainSummary
    agents_involved: list[str]


def _privilege_level(role: str) -> int:
    return PRIVILEGE_LEVELS.get(role.lower(), 3)


def _is_escalation(action: str) -> bool:
    return action.lower() in ESCALATION_ACTIONS or any(
        kw in action.lower()
        for kw in ("role", "permission", "privilege", "credential", "admin", "iam")
    )


def _is_bypass(policy_decision: str, effect: str) -> bool:
    return policy_decision.lower() in ("denied", "blocked") and effect.lower() not in ("", "none")


def _identify_critical_links(links: list[ChainLink]) -> list[int]:
    """Identify indices of critical links in the chain.

    A link is critical if it:
    - Is a bypass (policy denial circumvented)
    - Represents a large privilege jump (>= 2 levels)
    - Involves credential creation or rotation
    """
    critical: list[int] = []
    for i, link in enumerate(links):
        if link.is_bypass:
            critical.append(i)
            continue
        src = _privilege_level(link.source_role)
        tgt = _privilege_level(link.target_role)
        if tgt - src >= 2:
            critical.append(i)
            continue
        if any(kw in link.action.lower() for kw in ("create_credential", "create_token", "rotate")):
            critical.append(i)
    return critical


def _chain_severity(chain: PrivilegeChain) -> str:
    if chain.bypass_count > 0:
        return "critical"
    initial = _privilege_level(chain.initial_privilege)
    final = _privilege_level(chain.final_privilege)
    jump = final - initial
    if jump >= 4 or final >= PRIVILEGE_LEVELS.get("admin", 6):
        return "critical"
    if jump >= 2 or len(chain.critical_links) >= 2:
        return "high"
    if jump >= 1 or chain.chain_length >= 3:
        return "medium"
    return "low"


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> ChainReport:
    """Reconstruct privilege chains from event evidence."""
    if control_events is None:
        control_events = []

    agent_steps: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in control_events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        tool = ev.get("actual_tool", ev.get("tool", ""))
        if _is_escalation(tool) or _is_bypass(ev.get("policy_decision", ""), ev.get("effect", "")):
            agent_steps[agent].append({
                "timestamp": ev.get("timestamp", ""),
                "action": tool,
                "resource": ev.get("resource", ""),
                "effect": ev.get("effect", ""),
                "credential_id": ev.get("credential_id", ""),
                "role": ev.get("role", ""),
                "policy_decision": ev.get("policy_decision", ""),
                "source": "control",
            })

    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        tool = ev.get("claimed_tool", ev.get("tool", ""))
        if _is_escalation(tool) or _is_bypass(ev.get("policy_decision", ""), ev.get("effect", "")):
            agent_steps[agent].append({
                "timestamp": ev.get("timestamp", ""),
                "action": tool,
                "resource": ev.get("resource", ""),
                "effect": ev.get("effect", ""),
                "credential_id": ev.get("credential_id", ""),
                "role": ev.get("role", ""),
                "policy_decision": ev.get("policy_decision", ""),
                "source": "transcript",
            })

    chains: list[PrivilegeChain] = []
    for agent, steps in sorted(agent_steps.items()):
        steps.sort(key=lambda s: s["timestamp"])
        if not steps:
            continue

        links: list[ChainLink] = []
        current_role = steps[0].get("role", "none") or "none"
        creds: list[str] = []

        for step in steps:
            next_role = step.get("role", "") or current_role
            bypass = _is_bypass(step["policy_decision"], step["effect"])

            link = ChainLink(
                timestamp=step["timestamp"],
                agent_id=agent,
                action=step["action"],
                resource=step["resource"],
                effect=step["effect"],
                credential_id=step["credential_id"],
                source_role=current_role,
                target_role=next_role,
                is_bypass=bypass,
                policy_decision=step["policy_decision"],
            )
            links.append(link)

            if step["credential_id"] and step["credential_id"] not in creds:
                creds.append(step["credential_id"])

            if next_role != current_role:
                current_role = next_role

        critical_indices = _identify_critical_links(links)

        chain = PrivilegeChain(
            chain_id=f"PC-{len(chains)+1:03d}",
            agent_id=agent,
            links=links,
            initial_privilege=links[0].source_role,
            final_privilege=links[-1].target_role,
            chain_length=len(links),
            bypass_count=sum(1 for l in links if l.is_bypass),
            critical_links=critical_indices,
            credentials_used=creds,
        )
        chain.severity = _chain_severity(chain)
        chains.append(chain)

    chains.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c.severity, 4))

    sev_counts: dict[str, int] = defaultdict(int)
    for c in chains:
        sev_counts[c.severity] += 1

    total_links = sum(c.chain_length for c in chains)
    all_agents = sorted({c.agent_id for c in chains})

    summary = ChainSummary(
        total_chains=len(chains),
        critical_chains=sev_counts.get("critical", 0),
        high_chains=sev_counts.get("high", 0),
        total_links=total_links,
        total_bypasses=sum(c.bypass_count for c in chains),
        agents_involved=len(all_agents),
        max_chain_length=max((c.chain_length for c in chains), default=0),
        avg_chain_length=total_links / len(chains) if chains else 0.0,
        by_severity=dict(sev_counts),
    )

    return ChainReport(chains=chains, summary=summary, agents_involved=all_agents)


def format_text(report: ChainReport) -> str:
    lines: list[str] = []
    lines.append("Privilege Chain Reconstruction")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total chains:           {s.total_chains}")
    lines.append(f"  Critical chains:        {s.critical_chains}")
    lines.append(f"  High severity chains:   {s.high_chains}")
    lines.append(f"  Total links:            {s.total_links}")
    lines.append(f"  Total bypasses:         {s.total_bypasses}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Max chain length:       {s.max_chain_length}")
    lines.append(f"  Avg chain length:       {s.avg_chain_length:.1f}")
    lines.append("")

    if report.chains:
        for c in report.chains:
            lines.append(f"  [{c.severity.upper()}] {c.chain_id}: {c.agent_id}")
            lines.append(f"    Privilege: {c.initial_privilege} -> {c.final_privilege}")
            lines.append(f"    Length: {c.chain_length}, Bypasses: {c.bypass_count}, Critical links: {len(c.critical_links)}")
            if c.credentials_used:
                lines.append(f"    Credentials: {', '.join(c.credentials_used)}")
            for i, link in enumerate(c.links):
                marker = " [CRITICAL]" if i in c.critical_links else ""
                bypass = " [BYPASS]" if link.is_bypass else ""
                lines.append(f"      {i+1}. {link.timestamp}: {link.action} on {link.resource} ({link.source_role}->{link.target_role}){bypass}{marker}")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ChainReport) -> str:
    data = {
        "chains": [
            {
                **{k: v for k, v in asdict(c).items() if k != "links"},
                "links": [asdict(l) for l in c.links],
            }
            for c in report.chains
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def _load_events(evidence_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    control: list[dict[str, Any]] = []
    transcript_path = evidence_dir / "transcripts.jsonl"
    control_path = evidence_dir / "control_plane.jsonl"
    if transcript_path.exists():
        for line in transcript_path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    if control_path.exists():
        for line in control_path.read_text().splitlines():
            line = line.strip()
            if line:
                control.append(json.loads(line))
    return events, control
