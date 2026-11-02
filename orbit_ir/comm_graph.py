"""Agent communication graph builder and DOT exporter."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def build_comm_graph(messages: list[dict]) -> dict:
    """Build an adjacency structure from parsed messages.

    Returns ``{"edges": {(src, dst): count}, "nodes": set[str]}``.
    Messages without a ``recipient_agent_id`` are broadcast and skipped.
    Self-loops (sender == recipient) are kept.
    """
    edges: Counter[tuple[str, str]] = Counter()
    nodes: set[str] = set()
    for msg in messages:
        src = msg.get("agent_id")
        dst = msg.get("recipient_agent_id")
        if not src:
            continue
        nodes.add(src)
        if dst:
            nodes.add(dst)
            edges[(src, dst)] += 1
    return {"edges": dict(edges), "nodes": nodes}


def format_dot(graph: dict) -> str:
    """Render the communication graph as a DOT digraph."""
    lines = ["digraph comm {", '  rankdir=LR;', '  node [shape=box];']
    nodes = sorted(graph["nodes"])
    for n in nodes:
        lines.append(f'  "{n}";')

    max_weight = max(graph["edges"].values()) if graph["edges"] else 1
    for (src, dst), count in sorted(graph["edges"].items()):
        pw = max(1.0, 4.0 * count / max_weight)
        lines.append(f'  "{src}" -> "{dst}" [label="{count}" penwidth={pw:.1f}];')

    lines.append("}")
    return "\n".join(lines) + "\n"


def format_summary(graph: dict) -> dict:
    """Return a JSON-serialisable summary of the graph."""
    edges_list = [
        {"source": src, "target": dst, "weight": count}
        for (src, dst), count in sorted(graph["edges"].items())
    ]
    return {
        "nodes": sorted(graph["nodes"]),
        "edges": edges_list,
        "total_messages": sum(graph["edges"].values()),
        "total_edges": len(graph["edges"]),
    }


def load_and_build(input_dir: Path) -> dict:
    """Load messages.jsonl from a directory and build the graph."""
    messages_path = input_dir / "messages.jsonl"
    messages: list[dict] = []
    if messages_path.exists():
        with messages_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    messages.append(json.loads(line))
    return build_comm_graph(messages)
