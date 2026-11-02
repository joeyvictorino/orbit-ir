"""Agent communication topology with centrality analysis."""

from __future__ import annotations

import json
import math
from collections import defaultdict, deque
from pathlib import Path


def _betweenness_centrality(adj: dict[str, set[str]], nodes: list[str]) -> dict[str, float]:
    """Simplified Brandes algorithm for betweenness centrality."""
    centrality: dict[str, float] = {n: 0.0 for n in nodes}
    for s in nodes:
        stack: list[str] = []
        pred: dict[str, list[str]] = {n: [] for n in nodes}
        sigma: dict[str, int] = {n: 0 for n in nodes}
        sigma[s] = 1
        dist: dict[str, int] = {n: -1 for n in nodes}
        dist[s] = 0
        queue: deque[str] = deque([s])
        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in adj.get(v, set()):
                if dist[w] < 0:
                    queue.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta: dict[str, float] = {n: 0.0 for n in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                centrality[w] += delta[w]
    n = len(nodes)
    norm = (n - 1) * (n - 2) if n > 2 else 1
    if norm > 0:
        for k in centrality:
            centrality[k] /= norm
    return centrality


def _connected_components(adj_undirected: dict[str, set[str]], nodes: list[str]) -> list[list[str]]:
    """Find connected components via BFS."""
    visited: set[str] = set()
    components: list[list[str]] = []
    for start in nodes:
        if start in visited:
            continue
        component: list[str] = []
        queue: deque[str] = deque([start])
        visited.add(start)
        while queue:
            v = queue.popleft()
            component.append(v)
            for w in adj_undirected.get(v, set()):
                if w not in visited:
                    visited.add(w)
                    queue.append(w)
        components.append(sorted(component))
    return components


def build_topology(messages: list[dict]) -> dict:
    """Build agent communication topology from parsed messages.

    Returns a dict with nodes, edges, centrality scores, clusters,
    hub agents, isolated agents, and graph density.
    """
    node_msgs: dict[str, int] = defaultdict(int)
    node_first: dict[str, str] = {}
    node_last: dict[str, str] = {}
    edge_weight: dict[tuple[str, str], int] = defaultdict(int)
    edge_first: dict[tuple[str, str], str] = {}
    edge_last: dict[tuple[str, str], str] = {}

    for msg in messages:
        src = msg.get("agent_id")
        ts = msg.get("timestamp", "")
        if not src:
            continue
        node_msgs[src] += 1
        if src not in node_first or ts < node_first[src]:
            node_first[src] = ts
        if src not in node_last or ts > node_last[src]:
            node_last[src] = ts

        dst = msg.get("recipient_agent_id")
        if dst:
            node_msgs.setdefault(dst, 0)
            if dst not in node_first:
                node_first[dst] = ts
            if dst not in node_last:
                node_last[dst] = ts
            pair = (src, dst)
            edge_weight[pair] += 1
            if pair not in edge_first or ts < edge_first[pair]:
                edge_first[pair] = ts
            if pair not in edge_last or ts > edge_last[pair]:
                edge_last[pair] = ts

    all_nodes = sorted(node_msgs.keys())

    adj_directed: dict[str, set[str]] = defaultdict(set)
    adj_undirected: dict[str, set[str]] = defaultdict(set)
    degree: dict[str, int] = defaultdict(int)
    for (s, d) in edge_weight:
        adj_directed[s].add(d)
        adj_undirected[s].add(d)
        adj_undirected[d].add(s)
        degree[s] += 1
        degree[d] += 1

    centrality = _betweenness_centrality(adj_directed, all_nodes)
    components = _connected_components(adj_undirected, all_nodes)

    degrees = [degree.get(n, 0) for n in all_nodes]
    if degrees:
        mean_deg = sum(degrees) / len(degrees)
        variance = sum((d - mean_deg) ** 2 for d in degrees) / len(degrees)
        stddev = math.sqrt(variance)
        threshold = mean_deg + 2 * stddev
    else:
        mean_deg = 0.0
        threshold = 0.0

    hub_agents = sorted([n for n in all_nodes if degree.get(n, 0) > threshold])
    isolated = sorted([n for n in all_nodes if degree.get(n, 0) == 0])

    n = len(all_nodes)
    max_edges = n * (n - 1) if n > 1 else 1
    density = len(edge_weight) / max_edges if max_edges > 0 else 0.0

    nodes_list = [
        {
            "id": nid,
            "message_count": node_msgs[nid],
            "first_seen": node_first.get(nid, ""),
            "last_seen": node_last.get(nid, ""),
            "degree": degree.get(nid, 0),
            "centrality": round(centrality.get(nid, 0.0), 6),
        }
        for nid in all_nodes
    ]
    edges_list = [
        {
            "source": s,
            "target": d,
            "weight": edge_weight[(s, d)],
            "first_seen": edge_first.get((s, d), ""),
            "last_seen": edge_last.get((s, d), ""),
        }
        for (s, d) in sorted(edge_weight)
    ]

    return {
        "nodes": nodes_list,
        "edges": edges_list,
        "centrality": {n: round(centrality.get(n, 0.0), 6) for n in all_nodes},
        "clusters": components,
        "hub_agents": hub_agents,
        "isolated_agents": isolated,
        "density": round(density, 6),
        "node_count": n,
        "edge_count": len(edge_weight),
    }


def format_topology_text(topo: dict) -> str:
    """Render topology as a human-readable summary."""
    lines = [
        f"Agent Communication Topology",
        f"{'=' * 40}",
        f"Nodes: {topo['node_count']}  Edges: {topo['edge_count']}  Density: {topo['density']:.4f}",
        "",
    ]
    if topo["hub_agents"]:
        lines.append(f"Hub agents (degree > mean + 2*stddev): {', '.join(topo['hub_agents'])}")
    if topo["isolated_agents"]:
        lines.append(f"Isolated agents (no connections): {', '.join(topo['isolated_agents'])}")
    lines.append(f"Connected components: {len(topo['clusters'])}")
    lines.append("")

    top_central = sorted(topo["centrality"].items(), key=lambda x: -x[1])[:10]
    if top_central:
        lines.append("Top centrality scores:")
        for agent, score in top_central:
            lines.append(f"  {agent:30s}  {score:.6f}")
        lines.append("")

    top_edges = sorted(topo["edges"], key=lambda e: -e["weight"])[:10]
    if top_edges:
        lines.append("Heaviest edges:")
        for e in top_edges:
            lines.append(f"  {e['source']:20s} -> {e['target']:20s}  weight={e['weight']}")

    return "\n".join(lines) + "\n"


def format_topology_dot(topo: dict) -> str:
    """Render topology as DOT digraph."""
    lines = ["digraph topology {", "  rankdir=LR;", "  node [shape=box];"]
    for node in topo["nodes"]:
        label = f"{node['id']}\\n(c={node['centrality']:.3f})"
        lines.append(f'  "{node["id"]}" [label="{label}"];')
    max_w = max((e["weight"] for e in topo["edges"]), default=1)
    for e in topo["edges"]:
        pw = max(1.0, 4.0 * e["weight"] / max_w)
        lines.append(f'  "{e["source"]}" -> "{e["target"]}" [label="{e["weight"]}" penwidth={pw:.1f}];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def load_and_build(input_path: Path) -> dict:
    """Load messages and build topology."""
    if input_path.is_dir():
        msg_path = input_path / "messages.jsonl"
    else:
        msg_path = input_path
    messages: list[dict] = []
    if msg_path.exists():
        with msg_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    messages.append(json.loads(line))
    return build_topology(messages)
