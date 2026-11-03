"""Agent behavioral clustering for incident evidence.

Groups agents by behavioral similarity—tool usage patterns, resource
access profiles, timing characteristics, and action sequences—to
identify coordinated groups, outlier agents, and behavioral archetypes.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CLUSTER_METHODS = {
    "tool-profile": "Clustered by tool usage frequency distribution",
    "resource-profile": "Clustered by resource access patterns",
    "temporal-profile": "Clustered by activity timing patterns",
    "combined": "Clustered using combined behavioral features",
}


@dataclass
class AgentProfile:
    agent_id: str
    tool_counts: dict[str, int]
    resource_counts: dict[str, int]
    event_count: int
    unique_tools: int
    unique_resources: int
    active_duration: float


@dataclass
class BehaviorCluster:
    cluster_id: str
    method: str
    members: list[str]
    centroid_tools: dict[str, float]
    centroid_resources: dict[str, float]
    cohesion: float
    description: str


@dataclass
class ClusterOutlier:
    agent_id: str
    distance_from_nearest: float
    profile: AgentProfile
    reason: str


@dataclass
class ClusterSummary:
    total_agents: int
    total_clusters: int
    outlier_count: int
    largest_cluster_size: int
    average_cluster_size: float
    average_cohesion: float


@dataclass
class ClusterReport:
    clusters: list[BehaviorCluster]
    outliers: list[ClusterOutlier]
    profiles: list[AgentProfile]
    summary: ClusterSummary
    agents_involved: list[str]


def _build_profile(agent: str, events: list[dict[str, Any]]) -> AgentProfile:
    tool_counts: dict[str, int] = defaultdict(int)
    resource_counts: dict[str, int] = defaultdict(int)
    timestamps: list[str] = []

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if tool:
            tool_counts[tool] += 1
        resource = ev.get("resource", "")
        if resource:
            resource_counts[resource] += 1
        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    timestamps.sort()
    duration = 0.0
    if len(timestamps) >= 2:
        duration = len(timestamps)

    return AgentProfile(
        agent_id=agent,
        tool_counts=dict(tool_counts),
        resource_counts=dict(resource_counts),
        event_count=len(events),
        unique_tools=len(tool_counts),
        unique_resources=len(resource_counts),
        active_duration=duration,
    )


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    all_keys = set(vec_a) | set(vec_b)
    if not all_keys:
        return 1.0
    dot = sum(vec_a.get(k, 0.0) * vec_b.get(k, 0.0) for k in all_keys)
    mag_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
    mag_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _normalize_counts(counts: dict[str, int]) -> dict[str, float]:
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def _compute_centroid(profiles: list[AgentProfile], field: str) -> dict[str, float]:
    merged: dict[str, float] = defaultdict(float)
    for p in profiles:
        counts = getattr(p, field)
        norm = _normalize_counts(counts)
        for k, v in norm.items():
            merged[k] += v
    n = max(len(profiles), 1)
    return {k: round(v / n, 4) for k, v in merged.items()}


def _cluster_agents(
    profiles: list[AgentProfile],
    similarity_threshold: float = 0.3,
) -> tuple[list[BehaviorCluster], list[ClusterOutlier]]:
    if not profiles:
        return [], []

    tool_vecs = {p.agent_id: _normalize_counts(p.tool_counts) for p in profiles}

    assigned: dict[str, int] = {}
    clusters_members: list[list[str]] = []

    for p in profiles:
        agent = p.agent_id
        best_cluster = -1
        best_sim = -1.0

        for ci, members in enumerate(clusters_members):
            rep = members[0]
            sim = _cosine_similarity(tool_vecs[agent], tool_vecs[rep])
            if sim > best_sim:
                best_sim = sim
                best_cluster = ci

        if best_sim >= similarity_threshold and best_cluster >= 0:
            clusters_members[best_cluster].append(agent)
            assigned[agent] = best_cluster
        else:
            assigned[agent] = len(clusters_members)
            clusters_members.append([agent])

    profile_map = {p.agent_id: p for p in profiles}
    clusters: list[BehaviorCluster] = []
    outliers: list[ClusterOutlier] = []

    for ci, members in enumerate(clusters_members):
        member_profiles = [profile_map[m] for m in members]
        centroid_tools = _compute_centroid(member_profiles, "tool_counts")
        centroid_resources = _compute_centroid(member_profiles, "resource_counts")

        sims = []
        for m in members:
            sims.append(_cosine_similarity(tool_vecs[m], centroid_tools))
        cohesion = round(sum(sims) / max(len(sims), 1), 3)

        if len(members) == 1:
            min_dist = 1.0
            if len(clusters_members) > 1:
                for ci2, members2 in enumerate(clusters_members):
                    if ci2 == ci:
                        continue
                    for m2 in members2:
                        sim = _cosine_similarity(tool_vecs[members[0]], tool_vecs[m2])
                        dist = 1.0 - sim
                        min_dist = min(min_dist, dist)
            if min_dist > 0.7:
                outliers.append(ClusterOutlier(
                    agent_id=members[0],
                    distance_from_nearest=round(min_dist, 3),
                    profile=profile_map[members[0]],
                    reason=f"Singleton cluster, nearest neighbor distance {min_dist:.2f}",
                ))

        top_tools = sorted(centroid_tools.items(), key=lambda x: x[1], reverse=True)[:3]
        tool_desc = ", ".join(f"{t}({v:.2f})" for t, v in top_tools)

        clusters.append(BehaviorCluster(
            cluster_id=f"CLU-{ci + 1:03d}",
            method="combined",
            members=sorted(members),
            centroid_tools=centroid_tools,
            centroid_resources=centroid_resources,
            cohesion=cohesion,
            description=f"Cluster of {len(members)} agent(s), top tools: {tool_desc}",
        ))

    return clusters, outliers


def analyze_behavior_clusters(
    events: list[dict[str, Any]],
    similarity_threshold: float = 0.3,
) -> ClusterReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    profiles = []
    for agent, evts in sorted(agent_events.items()):
        profiles.append(_build_profile(agent, evts))

    clusters, outliers = _cluster_agents(profiles, similarity_threshold)

    all_agents = sorted(agent_events.keys())
    cluster_sizes = [len(c.members) for c in clusters]
    avg_cohesion = round(sum(c.cohesion for c in clusters) / max(len(clusters), 1), 3)

    return ClusterReport(
        clusters=clusters,
        outliers=outliers,
        profiles=profiles,
        summary=ClusterSummary(
            total_agents=len(profiles),
            total_clusters=len(clusters),
            outlier_count=len(outliers),
            largest_cluster_size=max(cluster_sizes) if cluster_sizes else 0,
            average_cluster_size=round(sum(cluster_sizes) / max(len(cluster_sizes), 1), 1),
            average_cohesion=avg_cohesion,
        ),
        agents_involved=all_agents,
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


def format_text(report: ClusterReport) -> str:
    lines: list[str] = []
    lines.append("Agent Behavioral Clustering Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:           {s.total_agents}")
    lines.append(f"  Clusters found:         {s.total_clusters}")
    lines.append(f"  Outlier agents:         {s.outlier_count}")
    lines.append(f"  Largest cluster:        {s.largest_cluster_size}")
    lines.append(f"  Average cluster size:   {s.average_cluster_size}")
    lines.append(f"  Average cohesion:       {s.average_cohesion}")
    lines.append("")

    for c in report.clusters:
        lines.append(f"  {c.cluster_id} (cohesion={c.cohesion})")
        lines.append(f"    Members: {', '.join(c.members[:10])}")
        if len(c.members) > 10:
            lines.append(f"    ... and {len(c.members) - 10} more")
        lines.append(f"    {c.description}")
        lines.append("")

    if report.outliers:
        lines.append("  Outlier Agents:")
        lines.append("  " + "-" * 60)
        for o in report.outliers:
            lines.append(f"    {o.agent_id}: distance={o.distance_from_nearest}, {o.reason}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ClusterReport) -> str:
    data = {
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "method": c.method,
                "members": c.members,
                "centroid_tools": c.centroid_tools,
                "centroid_resources": c.centroid_resources,
                "cohesion": c.cohesion,
                "description": c.description,
            }
            for c in report.clusters
        ],
        "outliers": [
            {
                "agent_id": o.agent_id,
                "distance_from_nearest": o.distance_from_nearest,
                "reason": o.reason,
                "profile": asdict(o.profile),
            }
            for o in report.outliers
        ],
        "profiles": [asdict(p) for p in report.profiles],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
