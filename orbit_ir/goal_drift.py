"""Agent goal drift detection for incident evidence.

Analyzes agent event sequences to detect goal deviation—agents
whose observed behavior diverges from their stated objectives,
gradually shifting targets, expanding scope beyond mandate, or
abandoning assigned goals in favor of emergent ones.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


GOAL_DEVIATION_TYPES = {
    "scope-expansion": "Agent expanded its operational scope beyond mandate",
    "objective-shift": "Agent shifted from stated to different objectives",
    "priority-inversion": "Agent inverted priority ordering of goals",
    "goal-abandonment": "Agent abandoned assigned goal(s) entirely",
    "emergent-goal": "Agent pursued goals not in its original mandate",
    "target-drift": "Agent gradually shifted target resources or entities",
}


@dataclass
class GoalState:
    timestamp: str
    declared_goals: list[str]
    observed_actions: list[str]
    resources_targeted: list[str]
    tools_used: list[str]


@dataclass
class DriftSegment:
    segment_id: str
    start_time: str
    end_time: str
    drift_type: str
    magnitude: float
    initial_goal_set: list[str]
    final_goal_set: list[str]
    resources_initial: list[str]
    resources_final: list[str]
    events: list[dict[str, Any]]
    description: str


@dataclass
class AgentDrift:
    agent_id: str
    drift_score: float
    segments: list[DriftSegment]
    goal_states: list[GoalState]
    total_goals_declared: int
    total_goals_observed: int
    abandoned_goals: list[str]
    emergent_goals: list[str]
    severity: str


@dataclass
class GoalDriftSummary:
    total_agents_analyzed: int
    agents_with_drift: int
    total_drift_segments: int
    by_drift_type: dict[str, int]
    by_severity: dict[str, int]
    average_drift_score: float
    max_drift_score: float


@dataclass
class GoalDriftReport:
    agent_drifts: list[AgentDrift]
    summary: GoalDriftSummary
    agents_involved: list[str]
    timeline: list[dict[str, Any]]


def _extract_goals(ev: dict[str, Any]) -> list[str]:
    goals = ev.get("goals", [])
    if isinstance(goals, list) and goals:
        return [str(g) for g in goals if g]
    goal = ev.get("goal", ev.get("objective", ""))
    if goal:
        return [str(goal)]
    return []


def _extract_target_resources(ev: dict[str, Any]) -> list[str]:
    resources = []
    res = ev.get("resource", "")
    if res:
        resources.append(res)
    targets = ev.get("targets", ev.get("target_resources", []))
    if isinstance(targets, list):
        resources.extend(str(t) for t in targets if t)
    return resources


def _jaccard_distance(set_a: set[str], set_b: set[str]) -> float:
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    intersection = set_a & set_b
    return 1.0 - (len(intersection) / len(union))


def _build_goal_states(events: list[dict[str, Any]], window_size: int = 10) -> list[GoalState]:
    states: list[GoalState] = []
    for i in range(0, len(events), max(window_size // 2, 1)):
        window = events[i:i + window_size]
        if not window:
            break
        goals: list[str] = []
        actions: list[str] = []
        resources: list[str] = []
        tools: list[str] = []
        for ev in window:
            goals.extend(_extract_goals(ev))
            resources.extend(_extract_target_resources(ev))
            tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
            if tool:
                tools.append(tool)
                actions.append(tool)

        states.append(GoalState(
            timestamp=window[0].get("timestamp", ""),
            declared_goals=sorted(set(goals)),
            observed_actions=sorted(set(actions)),
            resources_targeted=sorted(set(resources)),
            tools_used=sorted(set(tools)),
        ))
    return states


def _detect_scope_expansion(states: list[GoalState]) -> list[DriftSegment]:
    segments: list[DriftSegment] = []
    if len(states) < 2:
        return segments

    seg_counter = 0
    for i in range(1, len(states)):
        prev = states[i - 1]
        curr = states[i]
        prev_res = set(prev.resources_targeted)
        curr_res = set(curr.resources_targeted)
        new_resources = curr_res - prev_res
        if len(new_resources) >= 2 and len(curr_res) > len(prev_res) * 1.5:
            seg_counter += 1
            magnitude = min(len(new_resources) / max(len(prev_res), 1), 1.0)
            segments.append(DriftSegment(
                segment_id=f"SCOPE-{seg_counter:03d}",
                start_time=prev.timestamp,
                end_time=curr.timestamp,
                drift_type="scope-expansion",
                magnitude=round(magnitude, 3),
                initial_goal_set=prev.declared_goals,
                final_goal_set=curr.declared_goals,
                resources_initial=prev.resources_targeted,
                resources_final=curr.resources_targeted,
                events=[],
                description=f"Resource scope expanded from {len(prev_res)} to {len(curr_res)} targets (+{len(new_resources)} new)",
            ))
    return segments


def _detect_objective_shift(states: list[GoalState]) -> list[DriftSegment]:
    segments: list[DriftSegment] = []
    if len(states) < 2:
        return segments

    seg_counter = 0
    for i in range(1, len(states)):
        prev = states[i - 1]
        curr = states[i]
        prev_goals = set(prev.declared_goals)
        curr_goals = set(curr.declared_goals)
        if not prev_goals or not curr_goals:
            continue
        distance = _jaccard_distance(prev_goals, curr_goals)
        if distance >= 0.5:
            seg_counter += 1
            segments.append(DriftSegment(
                segment_id=f"SHIFT-{seg_counter:03d}",
                start_time=prev.timestamp,
                end_time=curr.timestamp,
                drift_type="objective-shift",
                magnitude=round(distance, 3),
                initial_goal_set=prev.declared_goals,
                final_goal_set=curr.declared_goals,
                resources_initial=prev.resources_targeted,
                resources_final=curr.resources_targeted,
                events=[],
                description=f"Objectives shifted with Jaccard distance {distance:.2f}",
            ))
    return segments


def _detect_goal_abandonment(
    states: list[GoalState],
) -> tuple[list[DriftSegment], list[str], list[str]]:
    segments: list[DriftSegment] = []
    if len(states) < 2:
        return segments, [], []

    first_goals = set(states[0].declared_goals)
    last_goals = set(states[-1].declared_goals)
    abandoned = sorted(first_goals - last_goals)
    emergent = sorted(last_goals - first_goals)

    if abandoned:
        segments.append(DriftSegment(
            segment_id="ABANDON-001",
            start_time=states[0].timestamp,
            end_time=states[-1].timestamp,
            drift_type="goal-abandonment",
            magnitude=round(len(abandoned) / max(len(first_goals), 1), 3),
            initial_goal_set=sorted(first_goals),
            final_goal_set=sorted(last_goals),
            resources_initial=states[0].resources_targeted,
            resources_final=states[-1].resources_targeted,
            events=[],
            description=f"Abandoned {len(abandoned)} goal(s): {', '.join(abandoned[:3])}",
        ))

    if emergent:
        segments.append(DriftSegment(
            segment_id="EMERGENT-001",
            start_time=states[0].timestamp,
            end_time=states[-1].timestamp,
            drift_type="emergent-goal",
            magnitude=round(len(emergent) / max(len(last_goals), 1), 3),
            initial_goal_set=sorted(first_goals),
            final_goal_set=sorted(last_goals),
            resources_initial=states[0].resources_targeted,
            resources_final=states[-1].resources_targeted,
            events=[],
            description=f"Pursued {len(emergent)} emergent goal(s): {', '.join(emergent[:3])}",
        ))

    return segments, abandoned, emergent


def _detect_target_drift(states: list[GoalState]) -> list[DriftSegment]:
    segments: list[DriftSegment] = []
    if len(states) < 3:
        return segments

    first_res = set(states[0].resources_targeted)
    last_res = set(states[-1].resources_targeted)
    if not first_res and not last_res:
        return segments

    distance = _jaccard_distance(first_res, last_res)
    if distance >= 0.6:
        segments.append(DriftSegment(
            segment_id="TARGET-001",
            start_time=states[0].timestamp,
            end_time=states[-1].timestamp,
            drift_type="target-drift",
            magnitude=round(distance, 3),
            initial_goal_set=states[0].declared_goals,
            final_goal_set=states[-1].declared_goals,
            resources_initial=states[0].resources_targeted,
            resources_final=states[-1].resources_targeted,
            events=[],
            description=f"Target resources drifted with distance {distance:.2f}",
        ))
    return segments


def _compute_drift_score(segments: list[DriftSegment]) -> float:
    if not segments:
        return 0.0
    magnitudes = [s.magnitude for s in segments]
    return round(min(sum(magnitudes) / len(magnitudes) + 0.1 * len(segments), 1.0), 3)


def _classify_severity(drift_score: float, segments: list[DriftSegment]) -> str:
    types = {s.drift_type for s in segments}
    if drift_score >= 0.7 or "goal-abandonment" in types:
        return "critical"
    if drift_score >= 0.5 or len(segments) >= 3:
        return "high"
    if drift_score >= 0.3 or len(segments) >= 2:
        return "medium"
    return "low"


def analyze_goal_drift(
    events: list[dict[str, Any]],
    window_size: int = 10,
) -> GoalDriftReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    agent_drifts: list[AgentDrift] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        states = _build_goal_states(evts_sorted, window_size)

        if len(states) < 2:
            continue

        segments: list[DriftSegment] = []
        segments.extend(_detect_scope_expansion(states))
        segments.extend(_detect_objective_shift(states))
        abandon_segs, abandoned, emergent = _detect_goal_abandonment(states)
        segments.extend(abandon_segs)
        segments.extend(_detect_target_drift(states))

        if not segments:
            continue

        drift_score = _compute_drift_score(segments)
        severity = _classify_severity(drift_score, segments)

        all_declared = set()
        all_observed = set()
        for st in states:
            all_declared.update(st.declared_goals)
            all_observed.update(st.observed_actions)

        agent_drifts.append(AgentDrift(
            agent_id=agent,
            drift_score=drift_score,
            segments=segments,
            goal_states=states,
            total_goals_declared=len(all_declared),
            total_goals_observed=len(all_observed),
            abandoned_goals=abandoned,
            emergent_goals=emergent,
            severity=severity,
        ))

    agent_drifts.sort(key=lambda d: d.drift_score, reverse=True)

    all_agents = sorted({d.agent_id for d in agent_drifts})
    type_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    total_segments = 0

    for d in agent_drifts:
        sev_counts[d.severity] += 1
        for seg in d.segments:
            type_counts[seg.drift_type] += 1
            total_segments += 1

    scores = [d.drift_score for d in agent_drifts]
    avg_score = round(sum(scores) / max(len(scores), 1), 3)
    max_score = max(scores) if scores else 0.0

    timeline = _build_timeline(agent_drifts)

    return GoalDriftReport(
        agent_drifts=agent_drifts,
        summary=GoalDriftSummary(
            total_agents_analyzed=len(agent_events),
            agents_with_drift=len(agent_drifts),
            total_drift_segments=total_segments,
            by_drift_type=dict(type_counts),
            by_severity=dict(sev_counts),
            average_drift_score=avg_score,
            max_drift_score=max_score,
        ),
        agents_involved=all_agents,
        timeline=timeline,
    )


def _build_timeline(drifts: list[AgentDrift]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in drifts:
        for seg in d.segments:
            entries.append({
                "timestamp": seg.start_time,
                "agent_id": d.agent_id,
                "segment_id": seg.segment_id,
                "drift_type": seg.drift_type,
                "magnitude": seg.magnitude,
                "severity": d.severity,
            })
    entries.sort(key=lambda e: e.get("timestamp", ""))
    return entries


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


def format_text(report: GoalDriftReport) -> str:
    lines: list[str] = []
    lines.append("Agent Goal Drift Analysis Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Agents analyzed:        {s.total_agents_analyzed}")
    lines.append(f"  Agents with drift:      {s.agents_with_drift}")
    lines.append(f"  Drift segments:         {s.total_drift_segments}")
    lines.append(f"  Average drift score:    {s.average_drift_score}")
    lines.append(f"  Max drift score:        {s.max_drift_score}")
    lines.append("")

    if s.by_drift_type:
        lines.append("  By Drift Type:")
        for dt, count in sorted(s.by_drift_type.items()):
            desc = GOAL_DEVIATION_TYPES.get(dt, dt)
            lines.append(f"    {dt}: {count} ({desc})")
        lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sev, count in sorted(s.by_severity.items()):
            lines.append(f"    {sev}: {count}")
        lines.append("")

    for d in report.agent_drifts:
        lines.append(f"  [{d.severity.upper()}] {d.agent_id} (score: {d.drift_score})")
        lines.append(f"    Goals declared: {d.total_goals_declared}, observed actions: {d.total_goals_observed}")
        if d.abandoned_goals:
            lines.append(f"    Abandoned: {', '.join(d.abandoned_goals[:5])}")
        if d.emergent_goals:
            lines.append(f"    Emergent: {', '.join(d.emergent_goals[:5])}")
        for seg in d.segments:
            lines.append(f"    [{seg.drift_type}] {seg.segment_id}: magnitude={seg.magnitude}")
            lines.append(f"      {seg.description}")
            lines.append(f"      Time: {seg.start_time} -> {seg.end_time}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: GoalDriftReport) -> str:
    data = {
        "agent_drifts": [
            {
                "agent_id": d.agent_id,
                "drift_score": d.drift_score,
                "severity": d.severity,
                "total_goals_declared": d.total_goals_declared,
                "total_goals_observed": d.total_goals_observed,
                "abandoned_goals": d.abandoned_goals,
                "emergent_goals": d.emergent_goals,
                "segments": [asdict(s) for s in d.segments],
                "goal_states": [asdict(gs) for gs in d.goal_states],
            }
            for d in report.agent_drifts
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
