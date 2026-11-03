"""Agent coordination analysis — measure handoff patterns, information sharing, and synchronization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Handoff:
    from_agent: str
    to_agent: str
    timestamp: str
    action: str


@dataclass
class CoordinationMetrics:
    total_agents: int = 0
    total_events: int = 0
    handoff_count: int = 0
    unique_pairs: int = 0
    info_sharing_events: int = 0
    synchronization_points: int = 0
    coordination_score: float = 0.0
    grade: str = "F"


@dataclass
class AgentPair:
    agent_a: str
    agent_b: str
    interaction_count: int = 0
    handoffs: int = 0
    shared_targets: list[str] = field(default_factory=list)


@dataclass
class CoordinationReport:
    metrics: CoordinationMetrics = field(default_factory=CoordinationMetrics)
    handoffs: list[Handoff] = field(default_factory=list)
    agent_pairs: list[AgentPair] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)


_INFO_SHARING_ACTIONS = {"share", "notify", "alert", "report", "escalate", "delegate", "forward"}
_SYNC_ACTIONS = {"sync", "coordinate", "acknowledge", "confirm", "approve", "wait", "join"}


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    for p in sorted(evidence_dir.iterdir()):
        if p.suffix == ".jsonl":
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def analyze(evidence_dir: Path) -> CoordinationReport:
    events = _load_events(evidence_dir)
    if not events:
        return CoordinationReport()

    agents: set[str] = set()
    agent_events: dict[str, list[dict]] = {}
    for e in events:
        aid = e.get("agent_id", "unknown")
        agents.add(aid)
        agent_events.setdefault(aid, []).append(e)

    handoffs = _detect_handoffs(events)
    info_sharing = sum(1 for e in events if e.get("action", "").lower() in _INFO_SHARING_ACTIONS)
    sync_points = sum(1 for e in events if e.get("action", "").lower() in _SYNC_ACTIONS)

    pairs = _build_pairs(events, agents)
    unique_pairs = len([p for p in pairs if p.interaction_count > 0])

    score = _compute_score(len(agents), len(handoffs), info_sharing, sync_points, len(events))

    metrics = CoordinationMetrics(
        total_agents=len(agents),
        total_events=len(events),
        handoff_count=len(handoffs),
        unique_pairs=unique_pairs,
        info_sharing_events=info_sharing,
        synchronization_points=sync_points,
        coordination_score=round(score, 2),
        grade=_score_to_grade(score),
    )

    return CoordinationReport(
        metrics=metrics,
        handoffs=handoffs,
        agent_pairs=[p for p in pairs if p.interaction_count > 0],
        agents=sorted(agents),
    )


def _detect_handoffs(events: list[dict]) -> list[Handoff]:
    handoffs: list[Handoff] = []
    prev_agent = None
    for e in events:
        agent = e.get("agent_id", "unknown")
        if prev_agent and agent != prev_agent:
            handoffs.append(Handoff(
                from_agent=prev_agent,
                to_agent=agent,
                timestamp=e.get("timestamp", ""),
                action=e.get("action", ""),
            ))
        prev_agent = agent
    return handoffs


def _build_pairs(events: list[dict], agents: set[str]) -> list[AgentPair]:
    agent_list = sorted(agents)
    pair_map: dict[tuple[str, str], AgentPair] = {}
    for i, a in enumerate(agent_list):
        for b in agent_list[i + 1:]:
            pair_map[(a, b)] = AgentPair(agent_a=a, agent_b=b)

    agent_targets: dict[str, set[str]] = {}
    for e in events:
        aid = e.get("agent_id", "unknown")
        target = e.get("target", e.get("dst_ip", ""))
        if target:
            agent_targets.setdefault(aid, set()).add(target)

    for (a, b), pair in pair_map.items():
        targets_a = agent_targets.get(a, set())
        targets_b = agent_targets.get(b, set())
        shared = targets_a & targets_b
        pair.shared_targets = sorted(shared)
        pair.interaction_count = len(shared)

    for e in events:
        agent = e.get("agent_id", "unknown")
        target_agent = e.get("target_agent", "")
        if target_agent and target_agent != agent:
            key = tuple(sorted([agent, target_agent]))
            if key in pair_map:
                pair_map[key].handoffs += 1
                pair_map[key].interaction_count += 1

    return list(pair_map.values())


def _compute_score(n_agents: int, n_handoffs: int, n_info: int, n_sync: int, n_events: int) -> float:
    if n_agents <= 1 or n_events == 0:
        return 0.0

    handoff_rate = min(1.0, n_handoffs / max(1, n_events) * 5)
    info_rate = min(1.0, n_info / max(1, n_events) * 10)
    sync_rate = min(1.0, n_sync / max(1, n_events) * 10)
    multi_agent = min(1.0, (n_agents - 1) / 4)

    return 0.30 * handoff_rate + 0.25 * info_rate + 0.25 * sync_rate + 0.20 * multi_agent


def _score_to_grade(score: float) -> str:
    if score >= 0.8:
        return "A"
    if score >= 0.6:
        return "B"
    if score >= 0.4:
        return "C"
    if score >= 0.2:
        return "D"
    return "F"


def format_text(report: CoordinationReport) -> str:
    m = report.metrics
    lines = [
        "Agent Coordination Analysis",
        "=" * 40,
        f"Total agents:           {m.total_agents}",
        f"Total events:           {m.total_events}",
        f"Handoff count:          {m.handoff_count}",
        f"Unique agent pairs:     {m.unique_pairs}",
        f"Info sharing events:    {m.info_sharing_events}",
        f"Synchronization points: {m.synchronization_points}",
        f"Coordination score:     {m.coordination_score:.2f} ({m.grade})",
        "",
    ]

    if report.handoffs:
        lines.append("Handoffs:")
        for h in report.handoffs[:20]:
            lines.append(f"  {h.timestamp}: {h.from_agent} -> {h.to_agent} ({h.action})")
        if len(report.handoffs) > 20:
            lines.append(f"  ... and {len(report.handoffs) - 20} more")

    if report.agent_pairs:
        lines.append("")
        lines.append("Agent pairs with interaction:")
        for p in report.agent_pairs:
            lines.append(f"  {p.agent_a} <-> {p.agent_b}: {p.interaction_count} interactions, {p.handoffs} handoffs")

    return "\n".join(lines) + "\n"


def format_json(report: CoordinationReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str) + "\n"
