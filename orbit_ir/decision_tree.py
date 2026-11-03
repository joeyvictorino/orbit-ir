"""Decision-tree reconstruction from agent event traces.

Reconstructs the decision paths agents took during an incident—branching
points where agents chose between alternatives, the options considered,
and the rationale for each choice. Detects anomalous decision patterns
like missing alternatives, suspiciously fast decisions, and decisions
that contradict prior stated reasoning.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class DecisionNode:
    agent_id: str
    event_id: str
    timestamp: str
    node_index: int
    description: str
    node_type: str
    alternatives_count: int
    chosen_action: str
    depth: int


@dataclass
class DecisionPath:
    agent_id: str
    path_id: str
    nodes: list[DecisionNode]
    total_decisions: int
    max_depth: int
    has_alternatives: bool
    avg_alternatives: float


@dataclass
class DecisionAnomaly:
    agent_id: str
    path_id: str
    anomaly_type: str
    severity: str
    description: str
    node_indices: list[int]


@dataclass
class AgentDecisionProfile:
    agent_id: str
    total_paths: int
    total_decisions: int
    avg_path_depth: float
    max_path_depth: int
    avg_alternatives: float
    anomaly_count: int


@dataclass
class DecisionTreeSummary:
    total_agents: int
    total_paths: int
    total_decisions: int
    total_anomalies: int
    by_anomaly_type: dict[str, int]
    deepest_path_agent: str
    most_anomalous_agent: str


@dataclass
class DecisionTreeReport:
    paths: list[DecisionPath]
    anomalies: list[DecisionAnomaly]
    profiles: list[AgentDecisionProfile]
    summary: DecisionTreeSummary
    agents_involved: list[str]


_DECISION_PATTERNS = re.compile(
    r"(?i)\b(decid(?:e|ed|es|ing)|chose|select(?:ed|ing|s)?|pick(?:ed|ing|s)?|"
    r"opt(?:ed|ing|s)?|went with|settled on|decision|choice|chosen)\b"
)
_ALTERNATIVE_PATTERNS = re.compile(
    r"(?i)\b(alternatively|or |option|could also|another approach|"
    r"on the other hand|instead|versus|vs\.?|either)\b"
)
_REJECTION_PATTERNS = re.compile(
    r"(?i)\b(reject|discard|rule out|not viable|won't work|"
    r"too risky|too expensive|infeasible|impossible)\b"
)
_BRANCH_PATTERNS = re.compile(
    r"(?i)\b(if |when |unless |in case|should .+ then|"
    r"depending on|contingent|conditional)\b"
)


def _classify_node(content: str) -> str:
    lower = content.lower()
    if _DECISION_PATTERNS.search(content):
        return "decision"
    if _REJECTION_PATTERNS.search(content):
        return "rejection"
    if _ALTERNATIVE_PATTERNS.search(content):
        return "alternative"
    if _BRANCH_PATTERNS.search(content):
        return "branch"
    if any(w in lower for w in ("evaluate", "assess", "weigh", "compare", "trade-off")):
        return "evaluation"
    if any(w in lower for w in ("action:", "execute", "implement", "proceed", "doing")):
        return "action"
    return "context"


def _count_alternatives(content: str) -> int:
    count = 0
    for pattern in (r"\b\d\)", r"\boption \d", r"\balternative \d", r"\bchoice \d"):
        count += len(re.findall(pattern, content, re.IGNORECASE))
    if _ALTERNATIVE_PATTERNS.search(content):
        count = max(count, 1)
    return count


def _extract_action(content: str) -> str:
    for pattern in (r"(?i)(?:chose|selected|decided|went with|picked)\s+(.{5,60}?)(?:\.|$|,)",
                    r"(?i)action:\s*(.{5,60}?)(?:\.|$|,)"):
        m = re.search(pattern, content)
        if m:
            return m.group(1).strip()
    return ""


def _extract_paths(events: list[dict[str, Any]]) -> list[DecisionPath]:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        content = ev.get("decision", ev.get("reasoning", ev.get("content", "")))
        if not content or not isinstance(content, str):
            continue
        agent_events[agent].append(ev)

    paths: list[DecisionPath] = []
    path_counter = 0

    for agent in sorted(agent_events):
        evs = sorted(agent_events[agent], key=lambda e: e.get("timestamp", ""))
        current_nodes: list[DecisionNode] = []
        depth = 0

        for i, ev in enumerate(evs):
            content = ev.get("decision", ev.get("reasoning", ev.get("content", "")))
            node_type = _classify_node(content)
            alternatives = _count_alternatives(content)
            action = _extract_action(content)

            if node_type == "branch":
                depth += 1

            current_nodes.append(DecisionNode(
                agent_id=agent,
                event_id=ev.get("event_id", f"node-{i}"),
                timestamp=ev.get("timestamp", ""),
                node_index=i,
                description=content[:200],
                node_type=node_type,
                alternatives_count=alternatives,
                chosen_action=action[:100],
                depth=depth,
            ))

            is_action = node_type == "action"
            is_decision = node_type == "decision" and action
            is_last = i == len(evs) - 1
            is_long = len(current_nodes) >= 15

            if is_action or is_decision or is_last or is_long:
                path_counter += 1
                total_decisions = sum(1 for n in current_nodes if n.node_type == "decision")
                alt_counts = [n.alternatives_count for n in current_nodes if n.alternatives_count > 0]
                avg_alt = round(sum(alt_counts) / len(alt_counts), 1) if alt_counts else 0.0
                max_d = max(n.depth for n in current_nodes) if current_nodes else 0

                paths.append(DecisionPath(
                    agent_id=agent,
                    path_id=f"path-{path_counter:04d}",
                    nodes=list(current_nodes),
                    total_decisions=total_decisions,
                    max_depth=max_d,
                    has_alternatives=any(n.alternatives_count > 0 for n in current_nodes),
                    avg_alternatives=avg_alt,
                ))

                if (is_action or is_decision) and not is_last:
                    current_nodes = []
                    depth = 0

    return paths


def _detect_no_alternatives(path: DecisionPath) -> list[DecisionAnomaly]:
    anomalies: list[DecisionAnomaly] = []
    if path.total_decisions >= 2 and not path.has_alternatives:
        decision_indices = [n.node_index for n in path.nodes if n.node_type == "decision"]
        anomalies.append(DecisionAnomaly(
            agent_id=path.agent_id,
            path_id=path.path_id,
            anomaly_type="no-alternatives-considered",
            severity="medium",
            description=(
                f"Agent '{path.agent_id}' made {path.total_decisions} decisions "
                f"without considering alternatives — may indicate predetermined actions"
            ),
            node_indices=decision_indices,
        ))
    return anomalies


def _detect_contradictions(path: DecisionPath) -> list[DecisionAnomaly]:
    anomalies: list[DecisionAnomaly] = []
    rejection_indices = []
    action_after_rejection = []

    for i, node in enumerate(path.nodes):
        if node.node_type == "rejection":
            rejection_indices.append(i)
        elif node.node_type == "action" and rejection_indices:
            action_content = node.description.lower()
            for ri in rejection_indices:
                rejected = path.nodes[ri].description.lower()
                overlap = set(rejected.split()) & set(action_content.split())
                if len(overlap) >= 3:
                    action_after_rejection.append((ri, i))

    if action_after_rejection:
        indices = list(set(idx for pair in action_after_rejection for idx in pair))
        anomalies.append(DecisionAnomaly(
            agent_id=path.agent_id,
            path_id=path.path_id,
            anomaly_type="contradiction",
            severity="high",
            description=(
                f"Agent '{path.agent_id}' took actions similar to previously "
                f"rejected options — reasoning may be inconsistent"
            ),
            node_indices=sorted(indices),
        ))
    return anomalies


def _detect_shallow_decisions(path: DecisionPath) -> list[DecisionAnomaly]:
    anomalies: list[DecisionAnomaly] = []
    quick_decisions = []

    for i, node in enumerate(path.nodes):
        if node.node_type != "decision":
            continue
        prior_eval = False
        for j in range(max(0, i - 2), i):
            if path.nodes[j].node_type in ("evaluation", "alternative", "branch"):
                prior_eval = True
                break
        if not prior_eval:
            quick_decisions.append(node.node_index)

    if len(quick_decisions) >= 2:
        anomalies.append(DecisionAnomaly(
            agent_id=path.agent_id,
            path_id=path.path_id,
            anomaly_type="shallow-decision",
            severity="medium",
            description=(
                f"Agent '{path.agent_id}' made {len(quick_decisions)} decisions "
                f"without prior evaluation — may indicate rushed or scripted behavior"
            ),
            node_indices=quick_decisions,
        ))
    return anomalies


def _detect_excessive_branching(path: DecisionPath, avg_depth: float) -> list[DecisionAnomaly]:
    anomalies: list[DecisionAnomaly] = []
    if avg_depth > 0 and path.max_depth > avg_depth * 3 and path.max_depth >= 5:
        branch_indices = [n.node_index for n in path.nodes if n.node_type == "branch"]
        anomalies.append(DecisionAnomaly(
            agent_id=path.agent_id,
            path_id=path.path_id,
            anomaly_type="excessive-branching",
            severity="high",
            description=(
                f"Agent '{path.agent_id}' has {path.max_depth} branch depth, "
                f"{path.max_depth / avg_depth:.1f}x average — may indicate analysis paralysis"
            ),
            node_indices=branch_indices,
        ))
    return anomalies


def analyze_decision_tree(events: list[dict[str, Any]]) -> DecisionTreeReport:
    paths = _extract_paths(events)

    if not paths:
        return DecisionTreeReport(
            paths=[],
            anomalies=[],
            profiles=[],
            summary=DecisionTreeSummary(
                total_agents=0,
                total_paths=0,
                total_decisions=0,
                total_anomalies=0,
                by_anomaly_type={},
                deepest_path_agent="",
                most_anomalous_agent="",
            ),
            agents_involved=[],
        )

    avg_depth = sum(p.max_depth for p in paths) / len(paths)

    anomalies: list[DecisionAnomaly] = []
    for path in paths:
        anomalies.extend(_detect_no_alternatives(path))
        anomalies.extend(_detect_contradictions(path))
        anomalies.extend(_detect_shallow_decisions(path))
        anomalies.extend(_detect_excessive_branching(path, avg_depth))

    anomalies.sort(key=lambda a: {"high": 0, "medium": 1, "low": 2}.get(a.severity, 3))

    agent_paths: dict[str, list[DecisionPath]] = defaultdict(list)
    for p in paths:
        agent_paths[p.agent_id].append(p)

    agent_anomalies: dict[str, int] = defaultdict(int)
    for a in anomalies:
        agent_anomalies[a.agent_id] += 1

    profiles: list[AgentDecisionProfile] = []
    for agent in sorted(agent_paths):
        ap = agent_paths[agent]
        total_decisions = sum(p.total_decisions for p in ap)
        depths = [p.max_depth for p in ap]
        alt_avgs = [p.avg_alternatives for p in ap if p.avg_alternatives > 0]

        profiles.append(AgentDecisionProfile(
            agent_id=agent,
            total_paths=len(ap),
            total_decisions=total_decisions,
            avg_path_depth=round(sum(depths) / len(depths), 1),
            max_path_depth=max(depths),
            avg_alternatives=round(sum(alt_avgs) / len(alt_avgs), 1) if alt_avgs else 0.0,
            anomaly_count=agent_anomalies.get(agent, 0),
        ))

    type_counts: dict[str, int] = defaultdict(int)
    for a in anomalies:
        type_counts[a.anomaly_type] += 1

    deepest = max(paths, key=lambda p: p.max_depth)
    most_anomalous = max(profiles, key=lambda p: p.anomaly_count).agent_id if profiles else ""
    total_decisions = sum(p.total_decisions for p in paths)

    return DecisionTreeReport(
        paths=paths,
        anomalies=anomalies,
        profiles=profiles,
        summary=DecisionTreeSummary(
            total_agents=len(profiles),
            total_paths=len(paths),
            total_decisions=total_decisions,
            total_anomalies=len(anomalies),
            by_anomaly_type=dict(type_counts),
            deepest_path_agent=deepest.agent_id,
            most_anomalous_agent=most_anomalous,
        ),
        agents_involved=sorted(agent_paths.keys()),
    )


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    for name in ("decisions.jsonl", "reasoning.jsonl", "events.jsonl"):
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


def format_text(report: DecisionTreeReport) -> str:
    lines: list[str] = []
    lines.append("Decision Tree Reconstruction Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:          {s.total_agents}")
    lines.append(f"  Total paths:           {s.total_paths}")
    lines.append(f"  Total decisions:       {s.total_decisions}")
    lines.append(f"  Anomalies detected:    {s.total_anomalies}")
    if s.deepest_path_agent:
        lines.append(f"  Deepest path agent:    {s.deepest_path_agent}")
    if s.most_anomalous_agent:
        lines.append(f"  Most anomalous agent:  {s.most_anomalous_agent}")
    lines.append("")

    if report.profiles:
        lines.append("  Agent Decision Profiles:")
        lines.append("  " + "-" * 60)
        for p in sorted(report.profiles, key=lambda x: x.anomaly_count, reverse=True):
            lines.append(
                f"    {p.agent_id}: {p.total_decisions} decisions, "
                f"avg depth {p.avg_path_depth:.1f}, "
                f"avg alternatives {p.avg_alternatives:.1f}"
            )
        lines.append("")

    if report.anomalies:
        lines.append("  Anomalies:")
        lines.append("  " + "-" * 60)
        for a in report.anomalies:
            lines.append(f"    [{a.severity.upper()}] {a.anomaly_type}: {a.agent_id}")
            lines.append(f"      {a.description}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: DecisionTreeReport) -> str:
    data = {
        "paths": [
            {
                "agent_id": p.agent_id,
                "path_id": p.path_id,
                "total_decisions": p.total_decisions,
                "max_depth": p.max_depth,
                "has_alternatives": p.has_alternatives,
                "avg_alternatives": p.avg_alternatives,
                "node_count": len(p.nodes),
            }
            for p in report.paths
        ],
        "anomalies": [
            {
                "agent_id": a.agent_id,
                "path_id": a.path_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "node_indices": a.node_indices,
            }
            for a in report.anomalies
        ],
        "profiles": [asdict(p) for p in report.profiles],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
