"""Agent behavioral drift analysis for agent evidence.

Tracks how agent behavior changes over time windows, detecting tool
usage drift, resource access drift, communication pattern changes,
and escalation tendency changes.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class DriftSignal:
    signal_id: str
    drift_type: str
    agent_id: str
    severity: str
    confidence: float
    description: str
    early_window: dict[str, Any] = field(default_factory=dict)
    late_window: dict[str, Any] = field(default_factory=dict)
    delta: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentDriftReport:
    signals: list[DriftSignal]
    summary: DriftSummary
    agents_analyzed: list[str]


@dataclass
class DriftSummary:
    total_signals: int
    critical_signals: int
    high_signals: int
    agents_drifting: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _split_windows(events: list[dict[str, Any]], split: float = 0.5) -> tuple[list[dict], list[dict]]:
    idx = int(len(events) * split)
    return events[:idx], events[idx:]


def _tool_distribution(events: list[dict[str, Any]]) -> Counter:
    tools: list[str] = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if tool:
            tools.append(tool)
    return Counter(tools)


def _resource_set(events: list[dict[str, Any]]) -> set[str]:
    return {ev.get("resource", "") for ev in events if ev.get("resource")}


ESCALATION_KEYWORDS = {
    "admin", "root", "sudo", "privilege", "escalat", "elevat",
    "role", "permission", "credential", "secret", "token",
}


def _escalation_count(events: list[dict[str, Any]]) -> int:
    count = 0
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", ""))).lower()
        resource = ev.get("resource", "").lower()
        effect = ev.get("effect", "").lower()
        combined = f"{tool} {resource} {effect}"
        if any(kw in combined for kw in ESCALATION_KEYWORDS):
            count += 1
    return count


def _communication_targets(events: list[dict[str, Any]]) -> set[str]:
    targets: set[str] = set()
    for ev in events:
        target = ev.get("target_agent", ev.get("recipient", ""))
        if target:
            targets.add(target)
    return targets


def _jensen_shannon(p: Counter, q: Counter) -> float:
    all_keys = set(p.keys()) | set(q.keys())
    if not all_keys:
        return 0.0
    p_total = sum(p.values()) or 1
    q_total = sum(q.values()) or 1

    p_dist = {k: p.get(k, 0) / p_total for k in all_keys}
    q_dist = {k: q.get(k, 0) / q_total for k in all_keys}
    m_dist = {k: (p_dist[k] + q_dist[k]) / 2 for k in all_keys}

    def kl(a: dict, b: dict) -> float:
        return sum(a[k] * math.log2(a[k] / b[k]) for k in all_keys if a[k] > 0 and b[k] > 0)

    return math.sqrt(max(0, (kl(p_dist, m_dist) + kl(q_dist, m_dist)) / 2))


def _detect_tool_drift(
    agent: str,
    early: list[dict[str, Any]],
    late: list[dict[str, Any]],
) -> DriftSignal | None:
    early_tools = _tool_distribution(early)
    late_tools = _tool_distribution(late)
    if not early_tools and not late_tools:
        return None

    distance = _jensen_shannon(early_tools, late_tools)
    if distance < 0.2:
        return None

    new_tools = set(late_tools.keys()) - set(early_tools.keys())
    dropped_tools = set(early_tools.keys()) - set(late_tools.keys())
    severity = "critical" if distance > 0.8 else "high" if distance > 0.5 else "medium"
    confidence = round(min(0.95, 0.4 + distance * 0.6), 2)

    parts = [f"Agent '{agent}' tool usage shifted (JS distance {distance:.2f})"]
    if new_tools:
        parts.append(f"new tools: {', '.join(sorted(new_tools)[:5])}")
    if dropped_tools:
        parts.append(f"dropped: {', '.join(sorted(dropped_tools)[:5])}")

    return DriftSignal(
        signal_id="",
        drift_type="tool-drift",
        agent_id=agent,
        severity=severity,
        confidence=confidence,
        description="; ".join(parts),
        early_window={"tools": dict(early_tools.most_common(5))},
        late_window={"tools": dict(late_tools.most_common(5))},
        delta={"js_distance": round(distance, 3), "new_tools": sorted(new_tools), "dropped_tools": sorted(dropped_tools)},
    )


def _detect_resource_drift(
    agent: str,
    early: list[dict[str, Any]],
    late: list[dict[str, Any]],
) -> DriftSignal | None:
    early_res = _resource_set(early)
    late_res = _resource_set(late)
    if not early_res and not late_res:
        return None

    new_resources = late_res - early_res
    if not new_resources:
        return None

    ratio = len(new_resources) / max(len(early_res), 1)
    if ratio < 0.3 and len(new_resources) < 2:
        return None

    severity = "high" if ratio > 1.0 else "medium" if ratio > 0.5 else "low"
    confidence = round(min(0.9, 0.4 + ratio * 0.3), 2)

    return DriftSignal(
        signal_id="",
        drift_type="resource-drift",
        agent_id=agent,
        severity=severity,
        confidence=confidence,
        description=f"Agent '{agent}' accessed {len(new_resources)} new resources not seen in early window",
        early_window={"resources": sorted(early_res)[:10]},
        late_window={"resources": sorted(late_res)[:10]},
        delta={"new_resources": sorted(new_resources)[:10], "ratio": round(ratio, 2)},
    )


def _detect_escalation_drift(
    agent: str,
    early: list[dict[str, Any]],
    late: list[dict[str, Any]],
) -> DriftSignal | None:
    early_esc = _escalation_count(early)
    late_esc = _escalation_count(late)
    early_rate = early_esc / max(len(early), 1)
    late_rate = late_esc / max(len(late), 1)

    if late_rate <= early_rate or late_esc < 2:
        return None

    increase = late_rate / max(early_rate, 0.001)
    if increase < 2.0:
        return None

    severity = "critical" if increase > 5 else "high" if increase > 3 else "medium"
    confidence = round(min(0.9, 0.4 + increase * 0.1), 2)

    return DriftSignal(
        signal_id="",
        drift_type="escalation-drift",
        agent_id=agent,
        severity=severity,
        confidence=confidence,
        description=f"Agent '{agent}' escalation rate increased {increase:.1f}x (early {early_rate:.2f}, late {late_rate:.2f})",
        early_window={"escalation_count": early_esc, "total": len(early), "rate": round(early_rate, 3)},
        late_window={"escalation_count": late_esc, "total": len(late), "rate": round(late_rate, 3)},
        delta={"increase_factor": round(increase, 1)},
    )


def _detect_communication_drift(
    agent: str,
    early: list[dict[str, Any]],
    late: list[dict[str, Any]],
) -> DriftSignal | None:
    early_targets = _communication_targets(early)
    late_targets = _communication_targets(late)

    if not early_targets and not late_targets:
        return None

    new_targets = late_targets - early_targets
    if not new_targets:
        return None

    severity = "high" if len(new_targets) >= 3 else "medium"
    confidence = round(min(0.85, 0.5 + len(new_targets) * 0.1), 2)

    return DriftSignal(
        signal_id="",
        drift_type="communication-drift",
        agent_id=agent,
        severity=severity,
        confidence=confidence,
        description=f"Agent '{agent}' started communicating with {len(new_targets)} new targets",
        early_window={"targets": sorted(early_targets)},
        late_window={"targets": sorted(late_targets)},
        delta={"new_targets": sorted(new_targets)},
    )


def analyze_agent_drift(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> AgentDriftReport:
    if control_events is None:
        control_events = []

    all_events = control_events + events
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for ev in all_events:
        agent = ev.get("agent_id", "")
        if agent:
            by_agent[agent].append(ev)

    signals: list[DriftSignal] = []
    for agent, agent_events in sorted(by_agent.items()):
        if len(agent_events) < 4:
            continue

        early, late = _split_windows(agent_events)

        for detector in [_detect_tool_drift, _detect_resource_drift, _detect_escalation_drift, _detect_communication_drift]:
            signal = detector(agent, early, late)
            if signal:
                signals.append(signal)

    signals.sort(key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s.severity, 4))

    for i, s in enumerate(signals):
        s.signal_id = f"AD-{i + 1:03d}"

    all_agents = sorted({s.agent_id for s in signals})
    type_counts = Counter(s.drift_type for s in signals)
    sev_counts = Counter(s.severity for s in signals)

    return AgentDriftReport(
        signals=signals,
        summary=DriftSummary(
            total_signals=len(signals),
            critical_signals=sev_counts.get("critical", 0),
            high_signals=sev_counts.get("high", 0),
            agents_drifting=len(all_agents),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
        ),
        agents_analyzed=all_agents,
    )


def _load_events(evidence_dir: Path) -> tuple[list[dict], list[dict]]:
    events: list[dict] = []
    control: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    control_file = evidence_dir / "control_plane.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    if control_file.exists():
        for line in control_file.read_text().splitlines():
            if line.strip():
                control.append(json.loads(line))
    return events, control


def format_text(report: AgentDriftReport) -> str:
    lines: list[str] = []
    lines.append("Agent Behavioral Drift Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total drift signals:    {s.total_signals}")
    lines.append(f"  Critical signals:       {s.critical_signals}")
    lines.append(f"  High severity:          {s.high_signals}")
    lines.append(f"  Agents drifting:        {s.agents_drifting}")
    lines.append("")

    if s.by_type:
        lines.append("  By type:")
        for t, c in sorted(s.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    for sig in report.signals:
        lines.append(f"  [{sig.severity.upper()}] {sig.signal_id}: {sig.drift_type}")
        lines.append(f"    Agent: {sig.agent_id}")
        lines.append(f"    {sig.description}")
        lines.append(f"    Confidence: {sig.confidence}")
        if sig.delta:
            for k, v in sig.delta.items():
                if isinstance(v, list):
                    lines.append(f"    {k}: {', '.join(str(x) for x in v[:5])}")
                else:
                    lines.append(f"    {k}: {v}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AgentDriftReport) -> str:
    data = {
        "signals": [asdict(s) for s in report.signals],
        "summary": asdict(report.summary),
        "agents_analyzed": report.agents_analyzed,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
