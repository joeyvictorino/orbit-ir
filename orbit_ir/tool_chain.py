"""Tool invocation chain analysis for agent event logs.

Builds chains of tool calls per agent session, detects multi-step
attack sequences, identifies tool dependency patterns and unusual
tool transitions.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ToolChain:
    chain_id: str
    agent_id: str
    tools: list[str]
    length: int
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    has_escalation: bool = False
    has_exfil_pattern: bool = False


@dataclass
class ToolTransition:
    from_tool: str
    to_tool: str
    count: int
    probability: float
    agents: list[str] = field(default_factory=list)


@dataclass
class SuspiciousChain:
    chain_id: str
    agent_id: str
    reason: str
    tools: list[str]
    risk_score: float


@dataclass
class ToolChainSummary:
    total_chains: int
    total_tool_calls: int
    unique_tools: int
    avg_chain_length: float
    max_chain_length: int
    suspicious_chains: int
    agents_analyzed: int
    escalation_chains: int
    exfil_chains: int


@dataclass
class ToolChainReport:
    chains: list[ToolChain]
    transitions: list[ToolTransition]
    suspicious: list[SuspiciousChain]
    summary: ToolChainSummary


RECON_TOOLS = {"list_files", "read_file", "search", "ls", "find", "cat", "head", "env", "whoami", "id", "ps"}
ESCALATION_TOOLS = {"sudo", "chmod", "chown", "setuid", "write_file", "exec", "shell", "run_command", "bash"}
EXFIL_TOOLS = {"curl", "wget", "send", "upload", "post", "http_request", "network", "connect", "scp", "nc"}


def _parse_ts(ev: dict) -> datetime | None:
    for k in ("timestamp", "ts", "time", "date", "created_at"):
        val = ev.get(k)
        if val:
            try:
                return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
    return None


def _tool_id(ev: dict) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", ev.get("action", ""))))


def _agent_id(ev: dict) -> str:
    return ev.get("agent", ev.get("agent_id", ev.get("source", "unknown")))


def analyze_tool_chains(
    events: list[dict[str, Any]],
    chain_gap_seconds: float = 120.0,
) -> ToolChainReport:
    by_agent: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for ev in events:
        ts = _parse_ts(ev)
        tool = _tool_id(ev)
        if ts and tool:
            by_agent[_agent_id(ev)].append((ts, tool))

    for agent in by_agent:
        by_agent[agent].sort(key=lambda x: x[0])

    chains: list[ToolChain] = []
    all_transitions: Counter = Counter()
    transition_agents: dict[tuple[str, str], set[str]] = defaultdict(set)
    total_calls = 0

    for agent, calls in sorted(by_agent.items()):
        current: list[tuple[datetime, str]] = []
        for ts, tool in calls:
            if current and (ts - current[-1][0]).total_seconds() > chain_gap_seconds:
                chains.append(_build_chain(len(chains), agent, current))
                _count_transitions(current, all_transitions, transition_agents, agent)
                current = []
            current.append((ts, tool))
        if current:
            chains.append(_build_chain(len(chains), agent, current))
            _count_transitions(current, all_transitions, transition_agents, agent)
        total_calls += len(calls)

    total_from: Counter = Counter()
    for (fr, _to), cnt in all_transitions.items():
        total_from[fr] += cnt

    transitions: list[ToolTransition] = []
    for (fr, to), cnt in all_transitions.most_common():
        prob = cnt / total_from[fr] if total_from[fr] > 0 else 0.0
        transitions.append(ToolTransition(
            from_tool=fr,
            to_tool=to,
            count=cnt,
            probability=round(prob, 3),
            agents=sorted(transition_agents[(fr, to)]),
        ))

    suspicious = _detect_suspicious(chains)
    all_tools = set()
    max_len = 0
    for c in chains:
        all_tools.update(c.tools)
        if c.length > max_len:
            max_len = c.length

    avg_len = sum(c.length for c in chains) / len(chains) if chains else 0.0

    return ToolChainReport(
        chains=chains,
        transitions=transitions,
        suspicious=suspicious,
        summary=ToolChainSummary(
            total_chains=len(chains),
            total_tool_calls=total_calls,
            unique_tools=len(all_tools),
            avg_chain_length=round(avg_len, 1),
            max_chain_length=max_len,
            suspicious_chains=len(suspicious),
            agents_analyzed=len(by_agent),
            escalation_chains=sum(1 for c in chains if c.has_escalation),
            exfil_chains=sum(1 for c in chains if c.has_exfil_pattern),
        ),
    )


def _build_chain(idx: int, agent: str, items: list[tuple[datetime, str]]) -> ToolChain:
    tools = [t for _, t in items]
    start = items[0][0]
    end = items[-1][0]
    dur = (end - start).total_seconds()

    tool_set = set(t.lower() for t in tools)
    has_esc = bool(tool_set & {t.lower() for t in ESCALATION_TOOLS})
    has_exfil = bool(tool_set & {t.lower() for t in EXFIL_TOOLS})

    return ToolChain(
        chain_id=f"TC-{idx:04d}",
        agent_id=agent,
        tools=tools,
        length=len(tools),
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        duration_seconds=round(dur, 2),
        has_escalation=has_esc,
        has_exfil_pattern=has_exfil,
    )


def _count_transitions(
    items: list[tuple[datetime, str]],
    counter: Counter,
    agents: dict[tuple[str, str], set[str]],
    agent: str,
) -> None:
    for i in range(len(items) - 1):
        pair = (items[i][1], items[i + 1][1])
        counter[pair] += 1
        agents[pair].add(agent)


def _detect_suspicious(chains: list[ToolChain]) -> list[SuspiciousChain]:
    suspicious: list[SuspiciousChain] = []
    for c in chains:
        reasons: list[str] = []
        risk = 0.0
        tool_lower = [t.lower() for t in c.tools]

        recon_count = sum(1 for t in tool_lower if t in {r.lower() for r in RECON_TOOLS})
        esc_count = sum(1 for t in tool_lower if t in {e.lower() for e in ESCALATION_TOOLS})
        exfil_count = sum(1 for t in tool_lower if t in {x.lower() for x in EXFIL_TOOLS})

        if recon_count > 0 and esc_count > 0:
            recon_idx = next(i for i, t in enumerate(tool_lower) if t in {r.lower() for r in RECON_TOOLS})
            esc_idx = next(i for i, t in enumerate(tool_lower) if t in {e.lower() for e in ESCALATION_TOOLS})
            if recon_idx < esc_idx:
                reasons.append("recon-to-escalation sequence")
                risk += 0.4

        if esc_count > 0 and exfil_count > 0:
            reasons.append("escalation-with-exfiltration")
            risk += 0.4

        if c.length > 10:
            reasons.append("long chain")
            risk += 0.2

        if reasons:
            suspicious.append(SuspiciousChain(
                chain_id=c.chain_id,
                agent_id=c.agent_id,
                reason="; ".join(reasons),
                tools=c.tools,
                risk_score=min(round(risk, 2), 1.0),
            ))

    suspicious.sort(key=lambda s: s.risk_score, reverse=True)
    return suspicious


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def format_text(report: ToolChainReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("Tool Chain Analysis")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"  Total chains:          {s.total_chains}")
    lines.append(f"  Total tool calls:      {s.total_tool_calls}")
    lines.append(f"  Unique tools:          {s.unique_tools}")
    lines.append(f"  Avg chain length:      {s.avg_chain_length}")
    lines.append(f"  Max chain length:      {s.max_chain_length}")
    lines.append(f"  Suspicious chains:     {s.suspicious_chains}")
    lines.append(f"  Escalation chains:     {s.escalation_chains}")
    lines.append(f"  Exfil chains:          {s.exfil_chains}")
    lines.append(f"  Agents analyzed:       {s.agents_analyzed}")
    lines.append("")

    if report.chains:
        lines.append("Chains:")
        for c in report.chains[:20]:
            flags = []
            if c.has_escalation:
                flags.append("ESC")
            if c.has_exfil_pattern:
                flags.append("EXFIL")
            flag_str = f" [{','.join(flags)}]" if flags else ""
            lines.append(f"  {c.chain_id}: {c.agent_id}, {c.length} tools, {c.duration_seconds}s{flag_str}")
            lines.append(f"    {' -> '.join(c.tools[:8])}")
        lines.append("")

    if report.transitions:
        lines.append("Top Transitions:")
        for t in report.transitions[:10]:
            lines.append(f"  {t.from_tool} -> {t.to_tool}: {t.count}x (p={t.probability})")
        lines.append("")

    if report.suspicious:
        lines.append("Suspicious Chains:")
        for s_chain in report.suspicious:
            lines.append(f"  {s_chain.chain_id}: {s_chain.agent_id} (risk={s_chain.risk_score})")
            lines.append(f"    Reason: {s_chain.reason}")
            lines.append(f"    Tools:  {' -> '.join(s_chain.tools[:8])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ToolChainReport) -> str:
    data = {
        "chains": [asdict(c) for c in report.chains],
        "transitions": [asdict(t) for t in report.transitions],
        "suspicious": [asdict(s) for s in report.suspicious],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
