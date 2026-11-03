"""Event dependency graph construction and analysis.

Builds directed graphs of event relationships—causal links, temporal
sequences, agent interactions, and resource sharing—to identify
critical paths, bottlenecks, and coordination patterns in agent
incident timelines.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class GraphNode:
    event_id: str
    agent_id: str
    timestamp: str
    event_type: str
    label: str


@dataclass
class GraphEdge:
    source: str
    target: str
    edge_type: str
    weight: float
    label: str


@dataclass
class GraphCluster:
    cluster_id: str
    nodes: list[str]
    description: str


@dataclass
class CriticalPath:
    path: list[str]
    total_weight: float
    description: str


@dataclass
class GraphSummary:
    total_nodes: int
    total_edges: int
    total_agents: int
    connected_components: int
    critical_path_length: int
    most_connected_node: str
    edge_types: dict[str, int]


@dataclass
class EventGraphReport:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    clusters: list[GraphCluster]
    critical_paths: list[CriticalPath]
    summary: GraphSummary
    agents_involved: list[str]


def _build_nodes(events: list[dict[str, Any]]) -> list[GraphNode]:
    nodes = []
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        eid = ev.get("event_id", ev.get("tool_call_id", ""))
        if not eid:
            continue
        etype = ev.get("event_type", ev.get("type", ev.get("tool", "unknown")))
        label = ev.get("description", ev.get("output", ""))[:80] if ev.get("description") or ev.get("output") else etype
        nodes.append(GraphNode(
            event_id=eid,
            agent_id=agent,
            timestamp=ev.get("timestamp", ""),
            event_type=etype,
            label=label,
        ))
    nodes.sort(key=lambda n: n.timestamp)
    return nodes


def _build_temporal_edges(nodes: list[GraphNode]) -> list[GraphEdge]:
    edges = []
    agent_last: dict[str, GraphNode] = {}
    for node in nodes:
        prev = agent_last.get(node.agent_id)
        if prev:
            edges.append(GraphEdge(
                source=prev.event_id,
                target=node.event_id,
                edge_type="temporal-sequence",
                weight=1.0,
                label=f"{prev.agent_id} sequence",
            ))
        agent_last[node.agent_id] = node
    return edges


def _build_resource_edges(
    events: list[dict[str, Any]],
    node_ids: set[str],
) -> list[GraphEdge]:
    edges = []
    resource_writers: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for ev in events:
        eid = ev.get("event_id", ev.get("tool_call_id", ""))
        if eid not in node_ids:
            continue
        resource = ev.get("resource", "")
        if not resource:
            continue
        action = ev.get("action", ev.get("tool", ""))
        agent = ev.get("agent_id", "")
        if action in ("write", "write_file", "create", "update", "put"):
            resource_writers[resource].append((eid, agent))

    resource_readers: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for ev in events:
        eid = ev.get("event_id", ev.get("tool_call_id", ""))
        if eid not in node_ids:
            continue
        resource = ev.get("resource", "")
        if not resource:
            continue
        action = ev.get("action", ev.get("tool", ""))
        agent = ev.get("agent_id", "")
        if action in ("read", "read_file", "get", "list", "fetch"):
            resource_readers[resource].append((eid, agent))

    for resource, writers in resource_writers.items():
        readers = resource_readers.get(resource, [])
        for w_eid, w_agent in writers:
            for r_eid, r_agent in readers:
                if w_eid != r_eid:
                    edges.append(GraphEdge(
                        source=w_eid,
                        target=r_eid,
                        edge_type="resource-dependency",
                        weight=2.0,
                        label=f"shared resource: {resource[:40]}",
                    ))
    return edges


def _build_causal_edges(events: list[dict[str, Any]], node_ids: set[str]) -> list[GraphEdge]:
    edges = []
    for ev in events:
        eid = ev.get("event_id", ev.get("tool_call_id", ""))
        if eid not in node_ids:
            continue
        parent = ev.get("parent_event_id", ev.get("triggered_by", ""))
        if parent and parent in node_ids:
            edges.append(GraphEdge(
                source=parent,
                target=eid,
                edge_type="causal",
                weight=3.0,
                label="triggered",
            ))
    return edges


def _find_components(nodes: list[GraphNode], edges: list[GraphEdge]) -> list[GraphCluster]:
    adj: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        adj[e.source].add(e.target)
        adj[e.target].add(e.source)

    visited: set[str] = set()
    components: list[list[str]] = []

    for node in nodes:
        if node.event_id in visited:
            continue
        component: list[str] = []
        stack = [node.event_id]
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            component.append(nid)
            for neighbor in adj.get(nid, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        components.append(sorted(component))

    clusters = []
    for i, comp in enumerate(sorted(components, key=len, reverse=True)):
        clusters.append(GraphCluster(
            cluster_id=f"COMP-{i + 1:03d}",
            nodes=comp,
            description=f"Connected component with {len(comp)} node(s)",
        ))
    return clusters


def _find_critical_path(nodes: list[GraphNode], edges: list[GraphEdge]) -> list[CriticalPath]:
    if not nodes or not edges:
        return []

    adj: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for e in edges:
        adj[e.source].append((e.target, e.weight))

    node_ids = [n.event_id for n in nodes]
    in_degree: dict[str, int] = defaultdict(int)
    for e in edges:
        in_degree[e.target] += 1

    roots = [nid for nid in node_ids if in_degree.get(nid, 0) == 0]
    if not roots:
        roots = [node_ids[0]]

    best_path: list[str] = []
    best_weight = 0.0

    for root in roots[:5]:
        dist: dict[str, float] = {root: 0.0}
        prev: dict[str, str] = {}
        stack = [root]
        visited_order: list[str] = []

        while stack:
            nid = stack.pop()
            if nid in visited_order:
                continue
            visited_order.append(nid)
            for neighbor, w in adj.get(nid, []):
                new_dist = dist.get(nid, 0) + w
                if new_dist > dist.get(neighbor, -1):
                    dist[neighbor] = new_dist
                    prev[neighbor] = nid
                    stack.append(neighbor)

        if dist:
            end = max(dist, key=dist.get)
            if dist[end] > best_weight:
                best_weight = dist[end]
                path = []
                cur = end
                while cur in prev:
                    path.append(cur)
                    cur = prev[cur]
                path.append(cur)
                path.reverse()
                best_path = path

    if best_path:
        return [CriticalPath(
            path=best_path,
            total_weight=round(best_weight, 2),
            description=f"Longest weighted path: {len(best_path)} nodes, weight {best_weight:.1f}",
        )]
    return []


def analyze_event_graph(events: list[dict[str, Any]]) -> EventGraphReport:
    nodes = _build_nodes(events)
    node_ids = {n.event_id for n in nodes}

    temporal_edges = _build_temporal_edges(nodes)
    resource_edges = _build_resource_edges(events, node_ids)
    causal_edges = _build_causal_edges(events, node_ids)

    all_edges = temporal_edges + resource_edges + causal_edges

    seen_edges: set[tuple[str, str, str]] = set()
    deduped: list[GraphEdge] = []
    for e in all_edges:
        key = (e.source, e.target, e.edge_type)
        if key not in seen_edges:
            seen_edges.add(key)
            deduped.append(e)

    clusters = _find_components(nodes, deduped)
    critical_paths = _find_critical_path(nodes, deduped)

    edge_type_counts: dict[str, int] = defaultdict(int)
    for e in deduped:
        edge_type_counts[e.edge_type] += 1

    degree: dict[str, int] = defaultdict(int)
    for e in deduped:
        degree[e.source] += 1
        degree[e.target] += 1
    most_connected = max(degree, key=degree.get, default="") if degree else ""

    agents = sorted({n.agent_id for n in nodes})

    return EventGraphReport(
        nodes=nodes,
        edges=deduped,
        clusters=clusters,
        critical_paths=critical_paths,
        summary=GraphSummary(
            total_nodes=len(nodes),
            total_edges=len(deduped),
            total_agents=len(agents),
            connected_components=len(clusters),
            critical_path_length=len(critical_paths[0].path) if critical_paths else 0,
            most_connected_node=most_connected,
            edge_types=dict(edge_type_counts),
        ),
        agents_involved=agents,
    )


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
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


def format_text(report: EventGraphReport) -> str:
    lines: list[str] = []
    lines.append("Event Dependency Graph Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total nodes:            {s.total_nodes}")
    lines.append(f"  Total edges:            {s.total_edges}")
    lines.append(f"  Agents:                 {s.total_agents}")
    lines.append(f"  Connected components:   {s.connected_components}")
    if s.most_connected_node:
        lines.append(f"  Most connected node:    {s.most_connected_node}")
    if s.critical_path_length:
        lines.append(f"  Critical path length:   {s.critical_path_length}")
    lines.append("")

    if s.edge_types:
        lines.append("  Edge Types:")
        for etype, count in sorted(s.edge_types.items()):
            lines.append(f"    {etype}: {count}")
        lines.append("")

    if report.clusters:
        lines.append("  Connected Components:")
        lines.append("  " + "-" * 60)
        for c in report.clusters[:10]:
            lines.append(f"    {c.cluster_id}: {len(c.nodes)} node(s)")
        if len(report.clusters) > 10:
            lines.append(f"    ... and {len(report.clusters) - 10} more")
        lines.append("")

    if report.critical_paths:
        lines.append("  Critical Paths:")
        lines.append("  " + "-" * 60)
        for cp in report.critical_paths:
            lines.append(f"    {cp.description}")
            path_str = " -> ".join(cp.path[:10])
            if len(cp.path) > 10:
                path_str += f" -> ... ({len(cp.path)} total)"
            lines.append(f"    Path: {path_str}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: EventGraphReport) -> str:
    data = {
        "nodes": [asdict(n) for n in report.nodes],
        "edges": [asdict(e) for e in report.edges],
        "clusters": [asdict(c) for c in report.clusters],
        "critical_paths": [asdict(cp) for cp in report.critical_paths],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
