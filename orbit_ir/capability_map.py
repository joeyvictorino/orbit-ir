"""Agent capability mapping from observed tool and resource usage.

Builds a map of each agent's capabilities based on the tools it invoked,
resources it accessed, and actions it performed during an incident.
Compares observed capabilities against expected baselines to flag
over-privileged agents or unauthorized capability usage.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CAPABILITY_CATEGORIES = {
    "read": ["read_file", "get", "list", "search", "query", "fetch", "view", "cat", "head", "tail"],
    "write": ["write_file", "create", "put", "post", "modify", "update", "append", "patch"],
    "delete": ["delete", "remove", "drop", "truncate", "purge", "rm"],
    "execute": ["execute_command", "run_shell", "bash", "exec", "invoke", "call"],
    "network": ["http_request", "curl", "wget", "fetch_url", "api_call", "connect"],
    "auth": ["login", "authenticate", "get_token", "refresh_token", "oauth", "sign_in"],
    "deploy": ["deploy", "publish", "release", "push", "upload", "install"],
    "admin": ["create_user", "grant_access", "elevate", "sudo", "chmod", "chown"],
}

RISK_TIERS = {
    "admin": 4,
    "deploy": 3,
    "execute": 3,
    "delete": 2,
    "write": 2,
    "auth": 2,
    "network": 1,
    "read": 0,
}


@dataclass
class AgentCapability:
    category: str
    tools: list[str] = field(default_factory=list)
    invocation_count: int = 0
    risk_tier: int = 0
    resources: list[str] = field(default_factory=list)


@dataclass
class AgentCapabilityProfile:
    agent_id: str
    capabilities: list[AgentCapability] = field(default_factory=list)
    total_invocations: int = 0
    unique_tools: int = 0
    max_risk_tier: int = 0
    risk_score: float = 0.0
    over_privileged: list[str] = field(default_factory=list)


@dataclass
class CapabilityMapSummary:
    total_agents: int = 0
    total_capabilities_observed: int = 0
    agents_with_admin: int = 0
    agents_with_delete: int = 0
    avg_risk_score: float = 0.0
    max_risk_score: float = 0.0
    highest_risk_agent: str = ""


@dataclass
class CapabilityMapReport:
    profiles: list[AgentCapabilityProfile] = field(default_factory=list)
    summary: CapabilityMapSummary = field(default_factory=CapabilityMapSummary)


_CATEGORY_ORDER = ["admin", "deploy", "execute", "delete", "auth", "network", "write", "read"]


def classify_capability(tool_name: str) -> str:
    lower = tool_name.lower()
    for category in _CATEGORY_ORDER:
        for p in CAPABILITY_CATEGORIES[category]:
            if p in lower:
                return category
    return "read"


def compute_risk_score(capabilities: list[AgentCapability]) -> float:
    if not capabilities:
        return 0.0
    weights = {"admin": 0.35, "deploy": 0.20, "execute": 0.15, "delete": 0.10, "write": 0.08, "auth": 0.07, "network": 0.03, "read": 0.02}
    score = 0.0
    for cap in capabilities:
        w = weights.get(cap.category, 0.02)
        intensity = min(cap.invocation_count / 10.0, 1.0)
        score += w * intensity
    return min(round(score, 4), 1.0)


def analyze_capability_map(events: list[dict[str, Any]]) -> CapabilityMapReport:
    agent_tools: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    agent_resources: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    agent_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for ev in events:
        agent_id = ev.get("agent_id") or ev.get("agent", "unknown")
        tool = ev.get("tool") or ev.get("tool_name") or ev.get("action", "")
        resource = ev.get("resource") or ev.get("target", "")
        if not tool:
            continue

        category = classify_capability(tool)
        if tool not in agent_tools[agent_id][category]:
            agent_tools[agent_id][category].append(tool)
        agent_counts[agent_id][category] += 1
        if resource and resource not in agent_resources[agent_id][category]:
            agent_resources[agent_id][category].append(resource)

    profiles = []
    for agent_id in sorted(agent_tools.keys()):
        caps = []
        all_tools = set()
        max_risk = 0
        for category in sorted(agent_tools[agent_id].keys()):
            tools = agent_tools[agent_id][category]
            all_tools.update(tools)
            tier = RISK_TIERS.get(category, 0)
            max_risk = max(max_risk, tier)
            caps.append(AgentCapability(
                category=category,
                tools=sorted(tools),
                invocation_count=agent_counts[agent_id][category],
                risk_tier=tier,
                resources=sorted(agent_resources[agent_id].get(category, [])),
            ))

        total_inv = sum(c.invocation_count for c in caps)
        risk = compute_risk_score(caps)
        over_priv = [c.category for c in caps if c.risk_tier >= 3]

        profiles.append(AgentCapabilityProfile(
            agent_id=agent_id,
            capabilities=caps,
            total_invocations=total_inv,
            unique_tools=len(all_tools),
            max_risk_tier=max_risk,
            risk_score=risk,
            over_privileged=over_priv,
        ))

    profiles.sort(key=lambda p: p.risk_score, reverse=True)
    summary = _build_summary(profiles)
    return CapabilityMapReport(profiles=profiles, summary=summary)


def _build_summary(profiles: list[AgentCapabilityProfile]) -> CapabilityMapSummary:
    if not profiles:
        return CapabilityMapSummary()
    total_caps = sum(len(p.capabilities) for p in profiles)
    admin_count = sum(1 for p in profiles if any(c.category == "admin" for c in p.capabilities))
    delete_count = sum(1 for p in profiles if any(c.category == "delete" for c in p.capabilities))
    scores = [p.risk_score for p in profiles]
    max_score = max(scores)
    highest = next((p.agent_id for p in profiles if p.risk_score == max_score), "")
    return CapabilityMapSummary(
        total_agents=len(profiles),
        total_capabilities_observed=total_caps,
        agents_with_admin=admin_count,
        agents_with_delete=delete_count,
        avg_risk_score=round(sum(scores) / len(scores), 4),
        max_risk_score=max_score,
        highest_risk_agent=highest,
    )


def format_text(report: CapabilityMapReport) -> str:
    lines = [f"Agent Capability Map ({report.summary.total_agents} agents)\n"]

    s = report.summary
    if s.agents_with_admin:
        lines.append(f"  Warning: {s.agents_with_admin} agents have admin capabilities")
    if s.agents_with_delete:
        lines.append(f"  Warning: {s.agents_with_delete} agents have delete capabilities")
    lines.append(f"  Average risk score: {s.avg_risk_score:.2f}")
    lines.append(f"  Highest risk: {s.highest_risk_agent} ({s.max_risk_score:.2f})")
    lines.append("")

    for p in report.profiles:
        flag = " [OVER-PRIVILEGED]" if p.over_privileged else ""
        lines.append(f"  {p.agent_id}: risk={p.risk_score:.2f}, {p.unique_tools} tools, {p.total_invocations} invocations{flag}")
        for cap in p.capabilities:
            tier_label = ["low", "standard", "elevated", "high", "critical"][min(cap.risk_tier, 4)]
            lines.append(f"    {cap.category:12s}  tier={tier_label:9s}  calls={cap.invocation_count}  tools={', '.join(cap.tools[:5])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: CapabilityMapReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(evidence_dir: str) -> list[dict[str, Any]]:
    events = []
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
