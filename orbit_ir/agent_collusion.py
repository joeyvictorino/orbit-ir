"""Agent collusion detection for incident event evidence.

Detects coordinated malicious behavior between agents: synchronized
actions, shared resource targeting, coordinated escalation, and
anomalous communication patterns.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class CollusionIndicator:
    """A single indicator of agent collusion."""
    indicator_id: str
    collusion_type: str
    agents: list[str]
    timestamp_start: str
    timestamp_end: str
    event_count: int
    severity: str
    confidence: float
    detail: str
    shared_resources: list[str] = field(default_factory=list)


@dataclass
class AgentPairProfile:
    """Collusion profile for a pair of agents."""
    agent_a: str
    agent_b: str
    shared_targets: int
    shared_credentials: int
    sync_events: int
    collusion_score: float


@dataclass
class CollusionSummary:
    total_indicators: int
    critical_indicators: int
    high_indicators: int
    agent_pairs: int
    agents_involved: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class CollusionReport:
    indicators: list[CollusionIndicator]
    pair_profiles: list[AgentPairProfile]
    summary: CollusionSummary
    agents_involved: list[str]


def _parse_timestamp(ts: str) -> float:
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ts)
    if not m:
        return 0.0
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    return y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60 + s


def _detect_synchronized_actions(
    by_agent: dict[str, list[dict[str, Any]]],
    sync_window: float = 5.0,
) -> list[CollusionIndicator]:
    indicators: list[CollusionIndicator] = []
    agents = sorted(by_agent.keys())
    for i in range(len(agents)):
        for j in range(i + 1, len(agents)):
            a, b = agents[i], agents[j]
            a_times = sorted((_parse_timestamp(e.get("timestamp", "")), e) for e in by_agent[a])
            b_times = sorted((_parse_timestamp(e.get("timestamp", "")), e) for e in by_agent[b])
            sync_count = 0
            sync_events: list[dict] = []
            for at, ae in a_times:
                if at == 0.0:
                    continue
                for bt, be in b_times:
                    if bt == 0.0:
                        continue
                    if abs(at - bt) <= sync_window:
                        sync_count += 1
                        sync_events.extend([ae, be])
                        break

            if sync_count >= 3:
                all_ts = sorted(e.get("timestamp", "") for e in sync_events if e.get("timestamp"))
                severity = "critical" if sync_count >= 10 else ("high" if sync_count >= 5 else "medium")
                indicators.append(CollusionIndicator(
                    indicator_id="",
                    collusion_type="synchronized-actions",
                    agents=[a, b],
                    timestamp_start=all_ts[0] if all_ts else "",
                    timestamp_end=all_ts[-1] if all_ts else "",
                    event_count=sync_count,
                    severity=severity,
                    confidence=min(0.9, 0.4 + sync_count * 0.05),
                    detail=f"{sync_count} synchronized actions between {a} and {b} within {sync_window}s windows",
                ))
    return indicators


def _detect_shared_targets(
    by_agent: dict[str, list[dict[str, Any]]],
) -> list[CollusionIndicator]:
    indicators: list[CollusionIndicator] = []
    agent_resources: dict[str, set[str]] = {}
    for agent, events in by_agent.items():
        resources = {e.get("resource", "") for e in events if e.get("resource")}
        if resources:
            agent_resources[agent] = resources

    agents = sorted(agent_resources.keys())
    for i in range(len(agents)):
        for j in range(i + 1, len(agents)):
            a, b = agents[i], agents[j]
            shared = agent_resources[a] & agent_resources[b]
            if len(shared) >= 3:
                all_events = by_agent[a] + by_agent[b]
                all_ts = sorted(e.get("timestamp", "") for e in all_events if e.get("timestamp"))
                severity = "high" if len(shared) >= 5 else "medium"
                indicators.append(CollusionIndicator(
                    indicator_id="",
                    collusion_type="shared-targets",
                    agents=[a, b],
                    timestamp_start=all_ts[0] if all_ts else "",
                    timestamp_end=all_ts[-1] if all_ts else "",
                    event_count=len(shared),
                    severity=severity,
                    confidence=min(0.85, 0.3 + len(shared) * 0.1),
                    detail=f"{a} and {b} share {len(shared)} target resources",
                    shared_resources=sorted(shared)[:10],
                ))
    return indicators


def _detect_coordinated_escalation(
    by_agent: dict[str, list[dict[str, Any]]],
    escalation_window: float = 120.0,
) -> list[CollusionIndicator]:
    indicators: list[CollusionIndicator] = []
    escalation_keywords = {"escalat", "elevat", "admin", "root", "privilege", "role", "grant", "permission"}

    agent_escalations: dict[str, list[dict]] = {}
    for agent, events in by_agent.items():
        esc_events = [
            e for e in events
            if any(kw in (e.get("effect", "") + e.get("tool", "") + e.get("actual_tool", "") + e.get("claimed_tool", "")).lower() for kw in escalation_keywords)
        ]
        if esc_events:
            agent_escalations[agent] = sorted(esc_events, key=lambda e: e.get("timestamp", ""))

    agents = sorted(agent_escalations.keys())
    for i in range(len(agents)):
        for j in range(i + 1, len(agents)):
            a, b = agents[i], agents[j]
            coord_count = 0
            for ea in agent_escalations[a]:
                ta = _parse_timestamp(ea.get("timestamp", ""))
                for eb in agent_escalations[b]:
                    tb = _parse_timestamp(eb.get("timestamp", ""))
                    if 0 < tb - ta <= escalation_window:
                        coord_count += 1

            if coord_count >= 2:
                all_events = agent_escalations[a] + agent_escalations[b]
                all_ts = sorted(e.get("timestamp", "") for e in all_events if e.get("timestamp"))
                indicators.append(CollusionIndicator(
                    indicator_id="",
                    collusion_type="coordinated-escalation",
                    agents=[a, b],
                    timestamp_start=all_ts[0] if all_ts else "",
                    timestamp_end=all_ts[-1] if all_ts else "",
                    event_count=coord_count,
                    severity="critical",
                    confidence=min(0.9, 0.5 + coord_count * 0.1),
                    detail=f"{coord_count} coordinated escalation sequences between {a} and {b}",
                ))
    return indicators


def _detect_credential_sharing(
    by_agent: dict[str, list[dict[str, Any]]],
) -> list[CollusionIndicator]:
    indicators: list[CollusionIndicator] = []
    cred_agents: dict[str, set[str]] = defaultdict(set)
    for agent, events in by_agent.items():
        for e in events:
            cred = e.get("credential_id", "")
            if cred:
                cred_agents[cred].add(agent)

    shared_creds = {cred: agents for cred, agents in cred_agents.items() if len(agents) >= 2}
    pair_shared: dict[tuple[str, str], list[str]] = defaultdict(list)
    for cred, agents in shared_creds.items():
        agents_list = sorted(agents)
        for i in range(len(agents_list)):
            for j in range(i + 1, len(agents_list)):
                pair_shared[(agents_list[i], agents_list[j])].append(cred)

    for (a, b), creds in pair_shared.items():
        if len(creds) >= 2:
            all_events = by_agent.get(a, []) + by_agent.get(b, [])
            all_ts = sorted(e.get("timestamp", "") for e in all_events if e.get("timestamp"))
            severity = "critical" if len(creds) >= 4 else ("high" if len(creds) >= 2 else "medium")
            indicators.append(CollusionIndicator(
                indicator_id="",
                collusion_type="credential-sharing",
                agents=[a, b],
                timestamp_start=all_ts[0] if all_ts else "",
                timestamp_end=all_ts[-1] if all_ts else "",
                event_count=len(creds),
                severity=severity,
                confidence=min(0.9, 0.5 + len(creds) * 0.1),
                detail=f"{a} and {b} share {len(creds)} credentials",
                shared_resources=sorted(creds)[:10],
            ))
    return indicators


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
    sync_window: float = 5.0,
    escalation_window: float = 120.0,
) -> CollusionReport:
    if control_events is None:
        control_events = []

    all_events = control_events + events
    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in all_events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    all_indicators: list[CollusionIndicator] = []
    all_indicators.extend(_detect_synchronized_actions(by_agent, sync_window))
    all_indicators.extend(_detect_shared_targets(by_agent))
    all_indicators.extend(_detect_coordinated_escalation(by_agent, escalation_window))
    all_indicators.extend(_detect_credential_sharing(by_agent))

    counter = 0
    for ind in all_indicators:
        counter += 1
        ind.indicator_id = f"AC-{counter:03d}"

    all_indicators.sort(key=lambda i: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(i.severity, 4))

    pair_profiles: list[AgentPairProfile] = []
    pair_data: dict[tuple[str, str], dict] = defaultdict(lambda: {"shared_targets": 0, "shared_creds": 0, "sync": 0, "score": 0.0})
    for ind in all_indicators:
        if len(ind.agents) == 2:
            key = (ind.agents[0], ind.agents[1])
            if ind.collusion_type == "shared-targets":
                pair_data[key]["shared_targets"] = ind.event_count
            elif ind.collusion_type == "credential-sharing":
                pair_data[key]["shared_creds"] = ind.event_count
            elif ind.collusion_type == "synchronized-actions":
                pair_data[key]["sync"] = ind.event_count
            pair_data[key]["score"] = max(pair_data[key]["score"], ind.confidence)

    for (a, b), data in sorted(pair_data.items()):
        pair_profiles.append(AgentPairProfile(
            agent_a=a,
            agent_b=b,
            shared_targets=data["shared_targets"],
            shared_credentials=data["shared_creds"],
            sync_events=data["sync"],
            collusion_score=data["score"],
        ))

    sev_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for ind in all_indicators:
        sev_counts[ind.severity] += 1
        type_counts[ind.collusion_type] += 1

    all_agents = sorted({a for ind in all_indicators for a in ind.agents})

    return CollusionReport(
        indicators=all_indicators,
        pair_profiles=pair_profiles,
        summary=CollusionSummary(
            total_indicators=len(all_indicators),
            critical_indicators=sev_counts.get("critical", 0),
            high_indicators=sev_counts.get("high", 0),
            agent_pairs=len(pair_profiles),
            agents_involved=len(all_agents),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
        ),
        agents_involved=all_agents,
    )


def format_text(report: CollusionReport) -> str:
    lines: list[str] = []
    lines.append("Agent Collusion Analysis")
    lines.append("=" * 62)
    lines.append("")
    s = report.summary
    lines.append(f"  Total indicators:       {s.total_indicators}")
    lines.append(f"  Critical indicators:    {s.critical_indicators}")
    lines.append(f"  High severity:          {s.high_indicators}")
    lines.append(f"  Agent pairs:            {s.agent_pairs}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")
    if s.by_type:
        lines.append("  By type:")
        for t, cnt in sorted(s.by_type.items()):
            lines.append(f"    {t}: {cnt}")
        lines.append("")
    for ind in report.indicators:
        lines.append(f"  [{ind.severity.upper()}] {ind.indicator_id}: {', '.join(ind.agents)}")
        lines.append(f"    Type: {ind.collusion_type}")
        lines.append(f"    {ind.detail}")
        lines.append(f"    Events: {ind.event_count}, Confidence: {ind.confidence:.0%}")
        if ind.shared_resources:
            lines.append(f"    Shared: {', '.join(ind.shared_resources[:5])}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: CollusionReport) -> str:
    data = {
        "indicators": [asdict(i) for i in report.indicators],
        "pair_profiles": [asdict(p) for p in report.pair_profiles],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def _load_events(evidence_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    control: list[dict[str, Any]] = []
    transcript_path = evidence_dir / "transcripts.jsonl"
    control_path = evidence_dir / "control_plane.jsonl"
    if transcript_path.exists():
        for line in transcript_path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    if control_path.exists():
        for line in control_path.read_text().splitlines():
            line = line.strip()
            if line:
                control.append(json.loads(line))
    return events, control
