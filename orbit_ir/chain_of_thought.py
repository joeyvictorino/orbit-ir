"""Chain-of-thought reasoning trace analysis.

Examines agent reasoning traces to detect anomalous thought patterns—
circular reasoning, logic jumps, goal drift within reasoning chains,
and inconsistencies between stated reasoning and actual actions that
may indicate deceptive or compromised agent behavior.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ReasoningStep:
    agent_id: str
    event_id: str
    timestamp: str
    step_index: int
    content: str
    step_type: str
    token_count: int


@dataclass
class ReasoningChain:
    agent_id: str
    chain_id: str
    steps: list[ReasoningStep]
    total_tokens: int
    depth: int
    has_conclusion: bool


@dataclass
class ChainAnomaly:
    agent_id: str
    chain_id: str
    anomaly_type: str
    severity: str
    description: str
    evidence_steps: list[int]


@dataclass
class AgentReasoningProfile:
    agent_id: str
    total_chains: int
    total_steps: int
    avg_chain_depth: float
    max_chain_depth: int
    conclusion_rate: float
    avg_tokens_per_step: float
    anomaly_count: int


@dataclass
class ChainOfThoughtSummary:
    total_agents: int
    total_chains: int
    total_steps: int
    total_anomalies: int
    by_anomaly_type: dict[str, int]
    deepest_chain_agent: str
    most_anomalous_agent: str


@dataclass
class ChainOfThoughtReport:
    chains: list[ReasoningChain]
    anomalies: list[ChainAnomaly]
    profiles: list[AgentReasoningProfile]
    summary: ChainOfThoughtSummary
    agents_involved: list[str]


_CONCLUSION_PATTERNS = re.compile(
    r"(?i)\b(therefore|thus|conclude|in conclusion|decision|final answer|"
    r"result is|i will|action:|chosen action)\b"
)
_CIRCULAR_PATTERNS = re.compile(
    r"(?i)\b(as (mentioned|stated|noted) (earlier|above|before|previously)|"
    r"going back to|returning to|revisiting|circling back)\b"
)
_JUMP_PATTERNS = re.compile(
    r"(?i)\b(suddenly|actually|wait|however|on second thought|"
    r"completely different|scratch that|never mind|ignore)\b"
)


def _classify_step(content: str) -> str:
    lower = content.lower()
    if any(w in lower for w in ("observe", "i see", "looking at", "input:", "given:")):
        return "observation"
    if any(w in lower for w in ("think", "reason", "because", "since", "if ", "consider")):
        return "reasoning"
    if _CONCLUSION_PATTERNS.search(content):
        return "conclusion"
    if any(w in lower for w in ("plan", "step 1", "first,", "next,", "then,")):
        return "planning"
    return "other"


def _extract_chains(events: list[dict[str, Any]]) -> list[ReasoningChain]:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        content = ev.get("reasoning", ev.get("thought", ev.get("content", "")))
        if not content or not isinstance(content, str):
            continue
        agent_events[agent].append(ev)

    chains: list[ReasoningChain] = []
    chain_counter = 0

    for agent in sorted(agent_events):
        evs = sorted(agent_events[agent], key=lambda e: e.get("timestamp", ""))
        current_steps: list[ReasoningStep] = []

        for i, ev in enumerate(evs):
            content = ev.get("reasoning", ev.get("thought", ev.get("content", "")))
            tokens = len(content.split())
            step_type = _classify_step(content)

            current_steps.append(ReasoningStep(
                agent_id=agent,
                event_id=ev.get("event_id", f"step-{i}"),
                timestamp=ev.get("timestamp", ""),
                step_index=i,
                content=content[:200],
                step_type=step_type,
                token_count=tokens,
            ))

            is_conclusion = step_type == "conclusion"
            is_last = i == len(evs) - 1
            is_long_chain = len(current_steps) >= 20

            if is_conclusion or is_last or is_long_chain:
                chain_counter += 1
                total_tokens = sum(s.token_count for s in current_steps)
                chains.append(ReasoningChain(
                    agent_id=agent,
                    chain_id=f"chain-{chain_counter:04d}",
                    steps=list(current_steps),
                    total_tokens=total_tokens,
                    depth=len(current_steps),
                    has_conclusion=is_conclusion,
                ))
                if is_conclusion and not is_last:
                    current_steps = []

    return chains


def _detect_circular(chain: ReasoningChain) -> list[ChainAnomaly]:
    anomalies: list[ChainAnomaly] = []
    circular_steps = []

    for step in chain.steps:
        if _CIRCULAR_PATTERNS.search(step.content):
            circular_steps.append(step.step_index)

    if len(circular_steps) >= 2:
        anomalies.append(ChainAnomaly(
            agent_id=chain.agent_id,
            chain_id=chain.chain_id,
            anomaly_type="circular-reasoning",
            severity="medium",
            description=(
                f"Agent '{chain.agent_id}' shows circular reasoning in "
                f"{len(circular_steps)} steps — may indicate stuck reasoning loop"
            ),
            evidence_steps=circular_steps,
        ))

    return anomalies


def _detect_logic_jumps(chain: ReasoningChain) -> list[ChainAnomaly]:
    anomalies: list[ChainAnomaly] = []
    jump_steps = []

    for step in chain.steps:
        if _JUMP_PATTERNS.search(step.content):
            jump_steps.append(step.step_index)

    if len(jump_steps) >= 3:
        anomalies.append(ChainAnomaly(
            agent_id=chain.agent_id,
            chain_id=chain.chain_id,
            anomaly_type="logic-jump",
            severity="medium",
            description=(
                f"Agent '{chain.agent_id}' has {len(jump_steps)} logic jumps "
                f"in reasoning chain — may indicate confused or manipulated reasoning"
            ),
            evidence_steps=jump_steps,
        ))

    return anomalies


def _detect_excessive_depth(chain: ReasoningChain, avg_depth: float) -> list[ChainAnomaly]:
    anomalies: list[ChainAnomaly] = []

    if avg_depth > 0 and chain.depth > avg_depth * 3 and chain.depth >= 10:
        anomalies.append(ChainAnomaly(
            agent_id=chain.agent_id,
            chain_id=chain.chain_id,
            anomaly_type="excessive-depth",
            severity="high",
            description=(
                f"Agent '{chain.agent_id}' reasoning chain has {chain.depth} steps, "
                f"{chain.depth / avg_depth:.1f}x the average — may indicate resource waste"
            ),
            evidence_steps=list(range(chain.depth)),
        ))

    return anomalies


def _detect_no_conclusion(chain: ReasoningChain) -> list[ChainAnomaly]:
    anomalies: list[ChainAnomaly] = []

    if not chain.has_conclusion and chain.depth >= 5:
        anomalies.append(ChainAnomaly(
            agent_id=chain.agent_id,
            chain_id=chain.chain_id,
            anomaly_type="no-conclusion",
            severity="low",
            description=(
                f"Agent '{chain.agent_id}' reasoning chain of {chain.depth} steps "
                f"has no conclusion — reasoning may be unresolved"
            ),
            evidence_steps=[chain.depth - 1],
        ))

    return anomalies


def analyze_chain_of_thought(events: list[dict[str, Any]]) -> ChainOfThoughtReport:
    chains = _extract_chains(events)

    if not chains:
        return ChainOfThoughtReport(
            chains=[],
            anomalies=[],
            profiles=[],
            summary=ChainOfThoughtSummary(
                total_agents=0,
                total_chains=0,
                total_steps=0,
                total_anomalies=0,
                by_anomaly_type={},
                deepest_chain_agent="",
                most_anomalous_agent="",
            ),
            agents_involved=[],
        )

    avg_depth = sum(c.depth for c in chains) / len(chains)

    anomalies: list[ChainAnomaly] = []
    for chain in chains:
        anomalies.extend(_detect_circular(chain))
        anomalies.extend(_detect_logic_jumps(chain))
        anomalies.extend(_detect_excessive_depth(chain, avg_depth))
        anomalies.extend(_detect_no_conclusion(chain))

    anomalies.sort(key=lambda a: {"high": 0, "medium": 1, "low": 2}.get(a.severity, 3))

    agent_chains: dict[str, list[ReasoningChain]] = defaultdict(list)
    for c in chains:
        agent_chains[c.agent_id].append(c)

    agent_anomalies: dict[str, int] = defaultdict(int)
    for a in anomalies:
        agent_anomalies[a.agent_id] += 1

    profiles: list[AgentReasoningProfile] = []
    for agent in sorted(agent_chains):
        ac = agent_chains[agent]
        total_steps = sum(c.depth for c in ac)
        total_tokens = sum(c.total_tokens for c in ac)
        depths = [c.depth for c in ac]
        conclusions = sum(1 for c in ac if c.has_conclusion)

        profiles.append(AgentReasoningProfile(
            agent_id=agent,
            total_chains=len(ac),
            total_steps=total_steps,
            avg_chain_depth=round(sum(depths) / len(depths), 1),
            max_chain_depth=max(depths),
            conclusion_rate=round(conclusions / len(ac), 3) if ac else 0.0,
            avg_tokens_per_step=round(total_tokens / max(total_steps, 1), 1),
            anomaly_count=agent_anomalies.get(agent, 0),
        ))

    type_counts: dict[str, int] = defaultdict(int)
    for a in anomalies:
        type_counts[a.anomaly_type] += 1

    deepest = max(chains, key=lambda c: c.depth)
    most_anomalous = max(profiles, key=lambda p: p.anomaly_count).agent_id if profiles else ""

    total_steps = sum(c.depth for c in chains)

    return ChainOfThoughtReport(
        chains=chains,
        anomalies=anomalies,
        profiles=profiles,
        summary=ChainOfThoughtSummary(
            total_agents=len(profiles),
            total_chains=len(chains),
            total_steps=total_steps,
            total_anomalies=len(anomalies),
            by_anomaly_type=dict(type_counts),
            deepest_chain_agent=deepest.agent_id,
            most_anomalous_agent=most_anomalous,
        ),
        agents_involved=sorted(agent_chains.keys()),
    )


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    for name in ("transcripts.jsonl", "reasoning.jsonl", "events.jsonl"):
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


def format_text(report: ChainOfThoughtReport) -> str:
    lines: list[str] = []
    lines.append("Chain-of-Thought Reasoning Trace Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:          {s.total_agents}")
    lines.append(f"  Total chains:          {s.total_chains}")
    lines.append(f"  Total steps:           {s.total_steps}")
    lines.append(f"  Anomalies detected:    {s.total_anomalies}")
    if s.deepest_chain_agent:
        lines.append(f"  Deepest chain agent:   {s.deepest_chain_agent}")
    if s.most_anomalous_agent:
        lines.append(f"  Most anomalous agent:  {s.most_anomalous_agent}")
    lines.append("")

    if report.profiles:
        lines.append("  Agent Reasoning Profiles:")
        lines.append("  " + "-" * 60)
        for p in sorted(report.profiles, key=lambda x: x.anomaly_count, reverse=True):
            lines.append(
                f"    {p.agent_id}: {p.total_chains} chains, "
                f"avg depth {p.avg_chain_depth:.1f}, "
                f"conclusion rate {p.conclusion_rate:.0%}"
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


def format_json(report: ChainOfThoughtReport) -> str:
    data = {
        "chains": [
            {
                "agent_id": c.agent_id,
                "chain_id": c.chain_id,
                "depth": c.depth,
                "total_tokens": c.total_tokens,
                "has_conclusion": c.has_conclusion,
                "step_count": len(c.steps),
            }
            for c in report.chains
        ],
        "anomalies": [
            {
                "agent_id": a.agent_id,
                "chain_id": a.chain_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "evidence_steps": a.evidence_steps,
            }
            for a in report.anomalies
        ],
        "profiles": [asdict(p) for p in report.profiles],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
