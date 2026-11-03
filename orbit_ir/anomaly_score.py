"""Composite anomaly scoring for agent behavior analysis.

Computes a multi-dimensional anomaly score for each agent based on
behavioral signals: tool usage frequency, timing patterns, resource
access breadth, and deviation from expected patterns.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SCORING_DIMENSIONS = {
    "tool-frequency": "Unusual tool call frequency relative to peers",
    "timing-regularity": "Suspicious timing patterns (too regular or too erratic)",
    "resource-breadth": "Breadth of resources accessed beyond normal scope",
    "action-diversity": "Diversity of action types (too narrow or too broad)",
    "error-rate": "Frequency of errors or denied actions",
    "payload-volume": "Volume of data processed or transferred",
}


@dataclass
class ScoringDimension:
    name: str
    score: float  # 0.0-1.0
    raw_value: float
    threshold: float
    description: str


@dataclass
class AgentAnomalyScore:
    agent_id: str
    composite_score: float  # 0.0-1.0
    risk_level: str  # "critical", "high", "medium", "low"
    dimensions: list[ScoringDimension] = field(default_factory=list)
    event_count: int = 0
    top_anomaly: str = ""


@dataclass
class AnomalyScoreSummary:
    total_agents: int
    agents_scored: int
    by_risk_level: dict[str, int] = field(default_factory=dict)
    avg_composite_score: float = 0.0
    max_composite_score: float = 0.0


@dataclass
class AnomalyScoreReport:
    scores: list[AgentAnomalyScore]
    summary: AnomalyScoreSummary


def score_anomalies(events: list[dict[str, Any]]) -> AnomalyScoreReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    if not agent_events:
        return AnomalyScoreReport(
            scores=[],
            summary=AnomalyScoreSummary(total_agents=0, agents_scored=0),
        )

    global_stats = _compute_global_stats(agent_events)

    scores: list[AgentAnomalyScore] = []
    for agent, evts in sorted(agent_events.items()):
        dims = _score_agent(agent, evts, global_stats)
        composite = _composite_score(dims)
        risk = _risk_level(composite)
        top = max(dims, key=lambda d: d.score).name if dims else ""

        scores.append(AgentAnomalyScore(
            agent_id=agent,
            composite_score=round(composite, 4),
            risk_level=risk,
            dimensions=dims,
            event_count=len(evts),
            top_anomaly=top,
        ))

    scores.sort(key=lambda s: -s.composite_score)

    risk_counts: dict[str, int] = defaultdict(int)
    for s in scores:
        risk_counts[s.risk_level] += 1

    composites = [s.composite_score for s in scores]
    avg = sum(composites) / len(composites) if composites else 0.0
    mx = max(composites) if composites else 0.0

    return AnomalyScoreReport(
        scores=scores,
        summary=AnomalyScoreSummary(
            total_agents=len(agent_events),
            agents_scored=len(scores),
            by_risk_level=dict(risk_counts),
            avg_composite_score=round(avg, 4),
            max_composite_score=round(mx, 4),
        ),
    )


def _compute_global_stats(agent_events: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    all_tool_counts: list[int] = []
    all_resource_counts: list[int] = []
    all_event_counts: list[int] = []

    for agent, evts in agent_events.items():
        all_event_counts.append(len(evts))
        tools = set()
        resources = set()
        for ev in evts:
            tool = ev.get("tool", ev.get("claimed_tool", ""))
            if tool:
                tools.add(tool)
            resource = ev.get("resource", "")
            if resource:
                resources.add(resource)
        all_tool_counts.append(len(tools))
        all_resource_counts.append(len(resources))

    return {
        "mean_events": _mean(all_event_counts),
        "std_events": _std(all_event_counts),
        "mean_tools": _mean(all_tool_counts),
        "std_tools": _std(all_tool_counts),
        "mean_resources": _mean(all_resource_counts),
        "std_resources": _std(all_resource_counts),
        "agent_count": len(agent_events),
    }


def _score_agent(
    agent: str,
    events: list[dict[str, Any]],
    global_stats: dict[str, Any],
) -> list[ScoringDimension]:
    dims: list[ScoringDimension] = []

    tools = Counter()
    resources = set()
    errors = 0
    total_bytes = 0
    timestamps: list[str] = []

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ""))
        if tool:
            tools[tool] += 1
        resource = ev.get("resource", "")
        if resource:
            resources.add(resource)
        if ev.get("status") in ("error", "denied", "failed"):
            errors += 1
        size = ev.get("bytes", 0) or ev.get("payload_size", 0) or ev.get("size", 0)
        if isinstance(size, (int, float)):
            total_bytes += int(size)
        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    n = len(events)

    freq_score = _z_score_norm(n, global_stats["mean_events"], global_stats["std_events"])
    dims.append(ScoringDimension(
        name="tool-frequency",
        score=round(freq_score, 4),
        raw_value=float(n),
        threshold=global_stats["mean_events"] + 2 * global_stats["std_events"],
        description=SCORING_DIMENSIONS["tool-frequency"],
    ))

    timing_score = _timing_regularity_score(timestamps)
    dims.append(ScoringDimension(
        name="timing-regularity",
        score=round(timing_score, 4),
        raw_value=timing_score,
        threshold=0.8,
        description=SCORING_DIMENSIONS["timing-regularity"],
    ))

    res_count = len(resources)
    breadth_score = _z_score_norm(res_count, global_stats["mean_resources"], global_stats["std_resources"])
    dims.append(ScoringDimension(
        name="resource-breadth",
        score=round(breadth_score, 4),
        raw_value=float(res_count),
        threshold=global_stats["mean_resources"] + 2 * global_stats["std_resources"],
        description=SCORING_DIMENSIONS["resource-breadth"],
    ))

    unique_tools = len(tools)
    diversity_score = _z_score_norm(unique_tools, global_stats["mean_tools"], global_stats["std_tools"])
    dims.append(ScoringDimension(
        name="action-diversity",
        score=round(diversity_score, 4),
        raw_value=float(unique_tools),
        threshold=global_stats["mean_tools"] + 2 * global_stats["std_tools"],
        description=SCORING_DIMENSIONS["action-diversity"],
    ))

    error_rate = errors / n if n > 0 else 0.0
    error_score = min(error_rate * 5.0, 1.0)
    dims.append(ScoringDimension(
        name="error-rate",
        score=round(error_score, 4),
        raw_value=round(error_rate, 4),
        threshold=0.1,
        description=SCORING_DIMENSIONS["error-rate"],
    ))

    volume_score = min(total_bytes / 1_000_000, 1.0) if total_bytes > 0 else 0.0
    dims.append(ScoringDimension(
        name="payload-volume",
        score=round(volume_score, 4),
        raw_value=float(total_bytes),
        threshold=500_000.0,
        description=SCORING_DIMENSIONS["payload-volume"],
    ))

    return dims


def _composite_score(dims: list[ScoringDimension]) -> float:
    if not dims:
        return 0.0
    weights = {
        "tool-frequency": 0.20,
        "timing-regularity": 0.15,
        "resource-breadth": 0.20,
        "action-diversity": 0.15,
        "error-rate": 0.15,
        "payload-volume": 0.15,
    }
    total = 0.0
    weight_sum = 0.0
    for d in dims:
        w = weights.get(d.name, 0.1)
        total += d.score * w
        weight_sum += w
    return total / weight_sum if weight_sum > 0 else 0.0


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _z_score_norm(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.5 if value > mean else 0.0
    z = (value - mean) / std
    return min(max(z / 4.0 + 0.5, 0.0), 1.0)


def _timing_regularity_score(timestamps: list[str]) -> float:
    if len(timestamps) < 3:
        return 0.0
    sorted_ts = sorted(timestamps)
    intervals: list[float] = []
    for i in range(1, len(sorted_ts)):
        a, b = sorted_ts[i - 1], sorted_ts[i]
        if a == b:
            intervals.append(0.0)
        else:
            intervals.append(1.0)

    if not intervals:
        return 0.0
    mean_interval = _mean(intervals)
    std_interval = _std(intervals)
    if mean_interval == 0:
        return 0.8
    cv = std_interval / mean_interval if mean_interval > 0 else 0.0
    if cv < 0.1:
        return 0.7
    return min(cv / 3.0, 1.0)


def _mean(values: list[float | int]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float | int]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
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


def format_text(report: AnomalyScoreReport) -> str:
    lines: list[str] = []
    lines.append("Composite Anomaly Score Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Agents scored:          {s.agents_scored}")
    lines.append(f"  Average score:          {s.avg_composite_score:.4f}")
    lines.append(f"  Max score:              {s.max_composite_score:.4f}")
    lines.append("")

    if s.by_risk_level:
        lines.append("  By Risk Level:")
        for risk, count in sorted(s.by_risk_level.items()):
            lines.append(f"    {risk}: {count}")
        lines.append("")

    for sc in report.scores:
        lines.append(f"  [{sc.risk_level.upper()}] {sc.agent_id}: {sc.composite_score:.4f}")
        lines.append(f"    Events: {sc.event_count}, Top anomaly: {sc.top_anomaly}")
        for d in sc.dimensions:
            bar = "#" * int(d.score * 20)
            lines.append(f"      {d.name:20s} {d.score:.3f} [{bar:20s}]")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AnomalyScoreReport) -> str:
    data = {
        "scores": [asdict(s) for s in report.scores],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
