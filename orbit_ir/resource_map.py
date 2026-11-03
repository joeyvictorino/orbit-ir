"""Resource access topology analysis for agent evidence.

Builds a graph of agent-to-resource interactions, detects concentration
of access, contention between agents, and escalation patterns where an
agent progressively touches more sensitive resources.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SENSITIVITY_KEYWORDS: dict[str, int] = {
    "secret": 5, "credential": 5, "password": 5, "token": 5, "key": 5,
    "admin": 4, "root": 4, "sudo": 4, "iam": 4, "rbac": 4,
    "policy": 3, "acl": 3, "permission": 3, "role": 3, "auth": 3,
    "config": 2, "cert": 2, "private": 2, "database": 2, "db": 2,
    "log": 1, "data": 1, "file": 1, "tmp": 0, "cache": 0,
}


def _resource_sensitivity(resource: str) -> int:
    if not resource:
        return 0
    lower = resource.lower()
    score = 0
    for keyword, weight in SENSITIVITY_KEYWORDS.items():
        if keyword in lower:
            score = max(score, weight)
    return score


def _sensitivity_label(score: int) -> str:
    if score >= 5:
        return "critical"
    if score >= 4:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


@dataclass
class AccessEdge:
    timestamp: str
    agent_id: str
    resource: str
    tool: str
    effect: str
    sensitivity: int
    source_file: str
    line: int


@dataclass
class ResourceNode:
    resource: str
    sensitivity: int
    sensitivity_label: str
    access_count: int
    agents: list[str]


@dataclass
class AgentNode:
    agent_id: str
    resources_accessed: int
    unique_resources: int
    max_sensitivity: int
    sensitive_accesses: int


@dataclass
class ConcentrationFinding:
    agent_id: str
    unique_resources: int
    sensitive_resources: int
    max_sensitivity: int
    description: str


@dataclass
class ContentionFinding:
    resource: str
    agents: list[str]
    access_count: int
    sensitivity: int
    description: str


@dataclass
class EscalationFinding:
    agent_id: str
    initial_sensitivity: int
    final_sensitivity: int
    sensitivity_progression: list[int]
    description: str


@dataclass
class ResourceMapSummary:
    total_agents: int
    total_resources: int
    total_edges: int
    concentration_findings: int
    contention_findings: int
    escalation_findings: int
    max_sensitivity_observed: int


@dataclass
class ResourceMapReport:
    agent_nodes: list[AgentNode]
    resource_nodes: list[ResourceNode]
    edges: list[AccessEdge]
    concentration: list[ConcentrationFinding]
    contention: list[ContentionFinding]
    escalation: list[EscalationFinding]
    summary: ResourceMapSummary


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        else:
            try:
                obj = json.loads(text)
                if isinstance(obj, list):
                    events.extend(obj)
                else:
                    events.append(obj)
            except json.JSONDecodeError:
                pass
    return events


def analyze_resource_map(
    events: list[dict[str, Any]],
    concentration_threshold: int = 5,
    contention_threshold: int = 2,
) -> ResourceMapReport:
    edges: list[AccessEdge] = []

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        resource = ev.get("resource", "")
        if not agent or not resource:
            continue
        tool = ev.get("claimed_tool", ev.get("actual_tool", ev.get("tool", "")))
        effect = ev.get("effect", "")
        ts = ev.get("timestamp", "")
        src = ev.get("source_file", "events.jsonl")
        sensitivity = _resource_sensitivity(resource)

        edges.append(AccessEdge(
            timestamp=ts,
            agent_id=agent,
            resource=resource,
            tool=tool,
            effect=effect,
            sensitivity=sensitivity,
            source_file=src,
            line=i + 1,
        ))

    edges.sort(key=lambda e: e.timestamp)

    resource_agents: dict[str, set[str]] = defaultdict(set)
    resource_count: dict[str, int] = defaultdict(int)
    resource_sens: dict[str, int] = {}
    agent_resources: dict[str, set[str]] = defaultdict(set)
    agent_access_count: dict[str, int] = defaultdict(int)
    agent_sensitive: dict[str, int] = defaultdict(int)
    agent_max_sens: dict[str, int] = defaultdict(int)
    agent_sens_timeline: dict[str, list[int]] = defaultdict(list)

    for edge in edges:
        resource_agents[edge.resource].add(edge.agent_id)
        resource_count[edge.resource] += 1
        resource_sens[edge.resource] = edge.sensitivity
        agent_resources[edge.agent_id].add(edge.resource)
        agent_access_count[edge.agent_id] += 1
        if edge.sensitivity >= 3:
            agent_sensitive[edge.agent_id] += 1
        agent_max_sens[edge.agent_id] = max(agent_max_sens[edge.agent_id], edge.sensitivity)
        agent_sens_timeline[edge.agent_id].append(edge.sensitivity)

    agent_nodes = []
    for agent in sorted(agent_resources):
        agent_nodes.append(AgentNode(
            agent_id=agent,
            resources_accessed=agent_access_count[agent],
            unique_resources=len(agent_resources[agent]),
            max_sensitivity=agent_max_sens[agent],
            sensitive_accesses=agent_sensitive[agent],
        ))

    resource_nodes = []
    for res in sorted(resource_sens):
        sens = resource_sens[res]
        resource_nodes.append(ResourceNode(
            resource=res,
            sensitivity=sens,
            sensitivity_label=_sensitivity_label(sens),
            access_count=resource_count[res],
            agents=sorted(resource_agents[res]),
        ))

    concentration = _detect_concentration(agent_resources, agent_sensitive, agent_max_sens, concentration_threshold)
    contention = _detect_contention(resource_agents, resource_count, resource_sens, contention_threshold)
    escalation = _detect_escalation(agent_sens_timeline)

    max_sens = max((e.sensitivity for e in edges), default=0)

    return ResourceMapReport(
        agent_nodes=agent_nodes,
        resource_nodes=resource_nodes,
        edges=edges,
        concentration=concentration,
        contention=contention,
        escalation=escalation,
        summary=ResourceMapSummary(
            total_agents=len(agent_nodes),
            total_resources=len(resource_nodes),
            total_edges=len(edges),
            concentration_findings=len(concentration),
            contention_findings=len(contention),
            escalation_findings=len(escalation),
            max_sensitivity_observed=max_sens,
        ),
    )


def _detect_concentration(
    agent_resources: dict[str, set[str]],
    agent_sensitive: dict[str, int],
    agent_max_sens: dict[str, int],
    threshold: int,
) -> list[ConcentrationFinding]:
    findings = []
    for agent in sorted(agent_resources):
        unique = len(agent_resources[agent])
        sensitive = agent_sensitive[agent]
        if unique >= threshold or sensitive >= 3:
            findings.append(ConcentrationFinding(
                agent_id=agent,
                unique_resources=unique,
                sensitive_resources=sensitive,
                max_sensitivity=agent_max_sens[agent],
                description=f"Agent '{agent}' accessed {unique} unique resources ({sensitive} sensitive)",
            ))
    findings.sort(key=lambda f: (-f.max_sensitivity, -f.sensitive_resources))
    return findings


def _detect_contention(
    resource_agents: dict[str, set[str]],
    resource_count: dict[str, int],
    resource_sens: dict[str, int],
    threshold: int,
) -> list[ContentionFinding]:
    findings = []
    for res in sorted(resource_agents):
        agents = resource_agents[res]
        if len(agents) >= threshold:
            findings.append(ContentionFinding(
                resource=res,
                agents=sorted(agents),
                access_count=resource_count[res],
                sensitivity=resource_sens[res],
                description=f"Resource '{res}' accessed by {len(agents)} agents ({resource_count[res]} times)",
            ))
    findings.sort(key=lambda f: (-f.sensitivity, -len(f.agents)))
    return findings


def _detect_escalation(
    agent_timelines: dict[str, list[int]],
) -> list[EscalationFinding]:
    findings = []
    for agent, timeline in sorted(agent_timelines.items()):
        if len(timeline) < 2:
            continue
        half = len(timeline) // 2
        first_half_max = max(timeline[:half]) if timeline[:half] else 0
        second_half_max = max(timeline[half:]) if timeline[half:] else 0
        if second_half_max > first_half_max and second_half_max >= 3:
            findings.append(EscalationFinding(
                agent_id=agent,
                initial_sensitivity=first_half_max,
                final_sensitivity=second_half_max,
                sensitivity_progression=timeline,
                description=f"Agent '{agent}' escalated from sensitivity {first_half_max} to {second_half_max}",
            ))
    findings.sort(key=lambda f: -(f.final_sensitivity - f.initial_sensitivity))
    return findings


def format_text(report: ResourceMapReport) -> str:
    lines: list[str] = []
    lines.append("Resource Access Topology Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Agents:                 {s.total_agents}")
    lines.append(f"  Resources:              {s.total_resources}")
    lines.append(f"  Access edges:           {s.total_edges}")
    lines.append(f"  Max sensitivity:        {s.max_sensitivity_observed}")
    lines.append(f"  Concentration issues:   {s.concentration_findings}")
    lines.append(f"  Contention issues:      {s.contention_findings}")
    lines.append(f"  Escalation patterns:    {s.escalation_findings}")
    lines.append("")

    if report.concentration:
        lines.append("  Concentration Findings:")
        lines.append("  " + "-" * 60)
        for f in report.concentration:
            lines.append(f"    [{_sensitivity_label(f.max_sensitivity).upper()}] {f.agent_id}: {f.unique_resources} resources, {f.sensitive_resources} sensitive")
        lines.append("")

    if report.contention:
        lines.append("  Contention Findings:")
        lines.append("  " + "-" * 60)
        for f in report.contention:
            lines.append(f"    [{_sensitivity_label(f.sensitivity).upper()}] {f.resource}: {len(f.agents)} agents ({', '.join(f.agents[:5])})")
        lines.append("")

    if report.escalation:
        lines.append("  Escalation Patterns:")
        lines.append("  " + "-" * 60)
        for f in report.escalation:
            lines.append(f"    {f.agent_id}: sensitivity {f.initial_sensitivity} -> {f.final_sensitivity}")
        lines.append("")

    if report.agent_nodes:
        lines.append("  Agent Summary:")
        lines.append("  " + "-" * 60)
        for a in sorted(report.agent_nodes, key=lambda x: -x.max_sensitivity):
            lines.append(f"    {a.agent_id}: {a.unique_resources} resources, max_sens={a.max_sensitivity}, sensitive_accesses={a.sensitive_accesses}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ResourceMapReport) -> str:
    data = {
        "agent_nodes": [asdict(a) for a in report.agent_nodes],
        "resource_nodes": [asdict(r) for r in report.resource_nodes],
        "edges": [asdict(e) for e in report.edges],
        "concentration": [asdict(c) for c in report.concentration],
        "contention": [asdict(c) for c in report.contention],
        "escalation": [asdict(e) for e in report.escalation],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
