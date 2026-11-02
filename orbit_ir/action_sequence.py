"""Action sequence pattern mining for agent event logs.

Finds frequent action subsequences, builds transition probability
matrices, and detects anomalous sequences in agent behavior.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ActionPattern:
    pattern_id: str
    sequence: list[str]
    frequency: int
    agents: list[str]
    avg_duration_seconds: float
    is_anomalous: bool


@dataclass
class TransitionProb:
    from_action: str
    to_action: str
    probability: float
    count: int


@dataclass
class ActionSequenceSummary:
    total_actions: int
    unique_actions: int
    total_patterns: int
    anomalous_patterns: int
    most_common_sequence: list[str]
    agents_analyzed: int


@dataclass
class ActionSequenceReport:
    patterns: list[ActionPattern]
    transitions: list[TransitionProb]
    anomalous_sequences: list[ActionPattern]
    summary: ActionSequenceSummary


def _extract_action(ev: dict) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", ev.get("action", ""))))


def analyze_action_sequences(
    events: list[dict[str, Any]],
    min_frequency: int = 2,
    max_sequence_length: int = 5,
) -> ActionSequenceReport:
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    all_actions: list[str] = []
    agent_sequences: dict[str, list[str]] = {}

    for agent in sorted(by_agent):
        actions = [_extract_action(ev) for ev in by_agent[agent]]
        actions = [a for a in actions if a]
        agent_sequences[agent] = actions
        all_actions.extend(actions)

    unique_actions = set(all_actions)

    transition_counts: dict[str, Counter] = defaultdict(Counter)
    for actions in agent_sequences.values():
        for i in range(len(actions) - 1):
            transition_counts[actions[i]][actions[i + 1]] += 1

    transitions: list[TransitionProb] = []
    for from_a, targets in sorted(transition_counts.items()):
        total = sum(targets.values())
        for to_a, count in targets.most_common():
            transitions.append(TransitionProb(
                from_action=from_a,
                to_action=to_a,
                probability=round(count / total, 3),
                count=count,
            ))

    low_prob_transitions = set()
    for t in transitions:
        if t.probability < 0.1 and t.count == 1:
            low_prob_transitions.add((t.from_action, t.to_action))

    subseq_counter: Counter = Counter()
    subseq_agents: dict[tuple, set] = defaultdict(set)

    for agent, actions in agent_sequences.items():
        for length in range(2, min(max_sequence_length + 1, len(actions) + 1)):
            for i in range(len(actions) - length + 1):
                subseq = tuple(actions[i:i + length])
                subseq_counter[subseq] += 1
                subseq_agents[subseq].add(agent)

    patterns: list[ActionPattern] = []
    anomalous: list[ActionPattern] = []
    pattern_counter = 0

    for subseq, freq in subseq_counter.most_common():
        pattern_counter += 1
        agents_list = sorted(subseq_agents[subseq])
        seq_list = list(subseq)

        has_low_prob = False
        for i in range(len(seq_list) - 1):
            if (seq_list[i], seq_list[i + 1]) in low_prob_transitions:
                has_low_prob = True
                break

        is_anom = freq == 1 or has_low_prob

        p = ActionPattern(
            pattern_id=f"AP-{pattern_counter:03d}",
            sequence=seq_list,
            frequency=freq,
            agents=agents_list,
            avg_duration_seconds=0.0,
            is_anomalous=is_anom,
        )
        if freq >= min_frequency or is_anom:
            patterns.append(p)
        if is_anom:
            anomalous.append(p)

    most_common: list[str] = []
    if subseq_counter:
        most_common = list(subseq_counter.most_common(1)[0][0])

    return ActionSequenceReport(
        patterns=patterns,
        transitions=transitions,
        anomalous_sequences=anomalous,
        summary=ActionSequenceSummary(
            total_actions=len(all_actions),
            unique_actions=len(unique_actions),
            total_patterns=len(patterns),
            anomalous_patterns=len(anomalous),
            most_common_sequence=most_common,
            agents_analyzed=len(agent_sequences),
        ),
    )


def format_text(report: ActionSequenceReport) -> str:
    lines: list[str] = []
    lines.append("Action Sequence Pattern Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total actions:          {s.total_actions}")
    lines.append(f"  Unique actions:         {s.unique_actions}")
    lines.append(f"  Patterns found:         {s.total_patterns}")
    lines.append(f"  Anomalous patterns:     {s.anomalous_patterns}")
    lines.append(f"  Agents analyzed:        {s.agents_analyzed}")
    if s.most_common_sequence:
        lines.append(f"  Most common sequence:   {' -> '.join(s.most_common_sequence)}")
    lines.append("")

    if report.patterns:
        lines.append("Top Patterns:")
        for p in report.patterns[:10]:
            marker = " [ANOMALOUS]" if p.is_anomalous else ""
            lines.append(f"  {p.pattern_id}: {' -> '.join(p.sequence)} (freq={p.frequency}){marker}")
        lines.append("")

    if report.transitions:
        lines.append("Transitions:")
        for t in report.transitions[:15]:
            lines.append(f"  {t.from_action} -> {t.to_action}: {t.probability:.1%} ({t.count})")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ActionSequenceReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "transitions": [asdict(t) for t in report.transitions],
        "anomalous_sequences": [asdict(a) for a in report.anomalous_sequences],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
