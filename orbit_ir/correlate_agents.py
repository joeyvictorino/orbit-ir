"""Cross-agent behavioral correlation analysis."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _type_vector(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(ev.get("type", "unknown") for ev in events)


def _jaccard(a: Counter[str], b: Counter[str]) -> float:
    keys = set(a) | set(b)
    if not keys:
        return 0.0
    intersection = sum(min(a.get(k, 0), b.get(k, 0)) for k in keys)
    union = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    return round(intersection / union, 4) if union else 0.0


def correlate_agents_analysis(
    input_path: Path,
    *,
    min_similarity: float = 0.3,
) -> dict[str, Any]:
    events = _load_events(input_path)

    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "unknown")
        by_agent[agent] += [ev]

    agents = sorted(by_agent.keys())
    vectors = {a: _type_vector(by_agent[a]) for a in agents}

    pairs: list[dict[str, Any]] = []
    for i, a1 in enumerate(agents):
        for a2 in agents[i + 1:]:
            sim = _jaccard(vectors[a1], vectors[a2])
            if sim >= min_similarity:
                shared = sorted(set(vectors[a1]) & set(vectors[a2]))
                pairs.append({
                    "agent_a": a1,
                    "agent_b": a2,
                    "similarity": sim,
                    "shared_types": shared,
                    "shared_type_count": len(shared),
                })

    pairs.sort(key=lambda p: p["similarity"], reverse=True)

    return {
        "total_events": len(events),
        "agent_count": len(agents),
        "agents": agents,
        "correlations": pairs,
        "correlation_count": len(pairs),
        "min_similarity": min_similarity,
    }


def format_correlate_agents_text(result: dict[str, Any]) -> str:
    lines = [
        f"Agent Correlation Analysis ({result['agent_count']} agents, {result['total_events']} events)",
        "=" * 60,
        "",
    ]

    pairs = result.get("correlations", [])
    if pairs:
        lines.append(f"Correlated pairs (similarity >= {result['min_similarity']}):")
        for p in pairs:
            lines.append(
                f"  {p['agent_a']} <-> {p['agent_b']}: "
                f"similarity={p['similarity']:.2%} "
                f"({p['shared_type_count']} shared types)"
            )
            if p["shared_types"]:
                lines.append(f"    types: {', '.join(p['shared_types'][:10])}")
    else:
        lines.append("No significant correlations found.")

    return "\n".join(lines)
