"""Insider threat pattern detection for agent evidence.

Analyzes agent behavior for patterns consistent with authorized agents
acting maliciously—slow data exfiltration, privilege accumulation
without business need, after-hours activity spikes, and access to
unrelated resources.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


EXFIL_INDICATORS = {
    "upload", "send", "transmit", "export", "transfer", "post",
    "write_external", "push_data", "sync_external",
}

PRIVILEGE_TOOLS = {
    "create_role", "modify_role", "assign_role", "grant_permission",
    "create_credential", "rotate_credential", "create_token",
    "modify_policy", "assume_role", "elevate", "modify_acl",
}

RECON_INDICATORS = {
    "list_users", "list_roles", "list_permissions", "list_secrets",
    "list_credentials", "enumerate", "scan", "discover", "probe",
}


@dataclass
class ThreatIndicator:
    timestamp: str
    agent_id: str
    event_id: str
    pattern_type: str
    action: str
    resource: str
    detail: str
    source_file: str
    line: int


@dataclass
class ThreatPattern:
    pattern_id: str
    agent_id: str
    pattern_type: str
    severity: str
    confidence: str
    indicators: list[ThreatIndicator]
    description: str
    risk_score: float


@dataclass
class ThreatSummary:
    total_patterns: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_confidence: dict[str, int]
    agents_flagged: int
    highest_risk_agent: str
    highest_risk_score: float


@dataclass
class InsiderThreatReport:
    patterns: list[ThreatPattern]
    summary: ThreatSummary
    agents_flagged: list[str]


def _is_exfil_action(tool: str) -> bool:
    lower = tool.lower()
    return any(ind in lower for ind in EXFIL_INDICATORS)


def _is_privilege_action(tool: str) -> bool:
    lower = tool.lower()
    return lower in PRIVILEGE_TOOLS or any(
        kw in lower for kw in ("role", "permission", "credential", "privilege")
    )


def _is_recon_action(tool: str) -> bool:
    lower = tool.lower()
    return lower in RECON_INDICATORS or any(
        kw in lower for kw in ("list_", "enumerate", "scan", "discover")
    )


def _parse_hour(ts: str) -> int | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).hour
        except ValueError:
            continue
    return None


def _classify_severity(indicators: list[ThreatIndicator], pattern_type: str) -> str:
    count = len(indicators)
    if pattern_type == "slow-exfiltration" and count >= 5:
        return "critical"
    if pattern_type == "privilege-accumulation" and count >= 4:
        return "critical"
    if count >= 6:
        return "critical"
    if count >= 3:
        return "high"
    if count >= 2:
        return "medium"
    return "low"


def _classify_confidence(indicators: list[ThreatIndicator], pattern_type: str) -> str:
    count = len(indicators)
    if count >= 5:
        return "high"
    if count >= 3:
        return "medium"
    return "low"


def _compute_risk_score(
    indicators: list[ThreatIndicator],
    severity: str,
    confidence: str,
) -> float:
    sev_weight = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}.get(severity, 0.25)
    conf_weight = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(confidence, 0.4)
    count_factor = min(len(indicators) / 10.0, 1.0)
    return round(sev_weight * conf_weight * (0.5 + 0.5 * count_factor), 3)


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> InsiderThreatReport:
    if control_events is None:
        control_events = []

    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for i, ev in enumerate(control_events):
        agent = ev.get("agent_id", "")
        if agent:
            ev_copy = dict(ev)
            ev_copy.setdefault("_source", "control_plane.jsonl")
            ev_copy.setdefault("_line", i + 1)
            agent_events[agent].append(ev_copy)

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        if agent:
            ev_copy = dict(ev)
            ev_copy.setdefault("_source", "transcripts.jsonl")
            ev_copy.setdefault("_line", i + 1)
            agent_events[agent].append(ev_copy)

    patterns: list[ThreatPattern] = []
    counter = 0

    for agent, evts in sorted(agent_events.items()):
        counter = _detect_slow_exfil(agent, evts, patterns, counter)
        counter = _detect_privilege_accumulation(agent, evts, patterns, counter)
        counter = _detect_after_hours(agent, evts, patterns, counter)
        counter = _detect_unrelated_access(agent, evts, patterns, counter)
        counter = _detect_recon_sweep(agent, evts, patterns, counter)

    patterns.sort(key=lambda p: p.risk_score, reverse=True)

    flagged = sorted({p.agent_id for p in patterns})
    by_type: dict[str, int] = defaultdict(int)
    by_sev: dict[str, int] = defaultdict(int)
    by_conf: dict[str, int] = defaultdict(int)
    max_risk = 0.0
    max_agent = ""
    for p in patterns:
        by_type[p.pattern_type] += 1
        by_sev[p.severity] += 1
        by_conf[p.confidence] += 1
        if p.risk_score > max_risk:
            max_risk = p.risk_score
            max_agent = p.agent_id

    return InsiderThreatReport(
        patterns=patterns,
        summary=ThreatSummary(
            total_patterns=len(patterns),
            by_type=dict(by_type),
            by_severity=dict(by_sev),
            by_confidence=dict(by_conf),
            agents_flagged=len(flagged),
            highest_risk_agent=max_agent,
            highest_risk_score=max_risk,
        ),
        agents_flagged=flagged,
    )


def _detect_slow_exfil(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[ThreatPattern],
    counter: int,
) -> int:
    indicators: list[ThreatIndicator] = []
    for ev in events:
        tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
        if _is_exfil_action(tool):
            resource = ev.get("resource", "")
            bytes_val = ev.get("bytes_transferred", ev.get("size", 0))
            indicators.append(ThreatIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("tool_call_id", ev.get("event_id", "")),
                pattern_type="slow-exfiltration",
                action=tool,
                resource=resource,
                detail=f"Transfer of {bytes_val} bytes to {resource}" if bytes_val else f"Exfil action: {tool}",
                source_file=ev.get("_source", ""),
                line=ev.get("_line", 0),
            ))

    if len(indicators) < 2:
        return counter

    counter += 1
    severity = _classify_severity(indicators, "slow-exfiltration")
    confidence = _classify_confidence(indicators, "slow-exfiltration")
    risk = _compute_risk_score(indicators, severity, confidence)

    patterns.append(ThreatPattern(
        pattern_id=f"IT-{counter:03d}",
        agent_id=agent,
        pattern_type="slow-exfiltration",
        severity=severity,
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' performed {len(indicators)} data exfiltration actions across multiple events",
        risk_score=risk,
    ))
    return counter


def _detect_privilege_accumulation(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[ThreatPattern],
    counter: int,
) -> int:
    indicators: list[ThreatIndicator] = []
    for ev in events:
        tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
        if _is_privilege_action(tool):
            indicators.append(ThreatIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("tool_call_id", ev.get("event_id", "")),
                pattern_type="privilege-accumulation",
                action=tool,
                resource=ev.get("resource", ""),
                detail=f"Privilege action: {tool} on {ev.get('resource', 'unknown')}",
                source_file=ev.get("_source", ""),
                line=ev.get("_line", 0),
            ))

    if len(indicators) < 2:
        return counter

    counter += 1
    severity = _classify_severity(indicators, "privilege-accumulation")
    confidence = _classify_confidence(indicators, "privilege-accumulation")
    risk = _compute_risk_score(indicators, severity, confidence)

    patterns.append(ThreatPattern(
        pattern_id=f"IT-{counter:03d}",
        agent_id=agent,
        pattern_type="privilege-accumulation",
        severity=severity,
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' accumulated {len(indicators)} privilege escalation actions",
        risk_score=risk,
    ))
    return counter


def _detect_after_hours(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[ThreatPattern],
    counter: int,
) -> int:
    indicators: list[ThreatIndicator] = []
    for ev in events:
        ts = ev.get("timestamp", "")
        hour = _parse_hour(ts)
        if hour is not None and (hour < 6 or hour >= 22):
            tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
            indicators.append(ThreatIndicator(
                timestamp=ts,
                agent_id=agent,
                event_id=ev.get("tool_call_id", ev.get("event_id", "")),
                pattern_type="after-hours-activity",
                action=tool,
                resource=ev.get("resource", ""),
                detail=f"Activity at hour {hour:02d}: {tool}",
                source_file=ev.get("_source", ""),
                line=ev.get("_line", 0),
            ))

    if len(indicators) < 3:
        return counter

    counter += 1
    severity = _classify_severity(indicators, "after-hours-activity")
    confidence = _classify_confidence(indicators, "after-hours-activity")
    risk = _compute_risk_score(indicators, severity, confidence)

    patterns.append(ThreatPattern(
        pattern_id=f"IT-{counter:03d}",
        agent_id=agent,
        pattern_type="after-hours-activity",
        severity=severity,
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' performed {len(indicators)} actions during after-hours (22:00-06:00)",
        risk_score=risk,
    ))
    return counter


def _detect_unrelated_access(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[ThreatPattern],
    counter: int,
) -> int:
    resources_by_category: dict[str, set[str]] = defaultdict(set)
    resource_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        resource = ev.get("resource", "")
        if not resource:
            continue
        parts = resource.lower().split("/")
        category = parts[0] if parts else "unknown"
        resources_by_category[category].add(resource)
        resource_events[category].append(ev)

    if len(resources_by_category) < 4:
        return counter

    indicators: list[ThreatIndicator] = []
    for cat, evts in resource_events.items():
        ev = evts[0]
        tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
        indicators.append(ThreatIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("tool_call_id", ev.get("event_id", "")),
            pattern_type="unrelated-resource-access",
            action=tool,
            resource=ev.get("resource", ""),
            detail=f"Accessed {len(resources_by_category[cat])} resource(s) in category '{cat}'",
            source_file=ev.get("_source", ""),
            line=ev.get("_line", 0),
        ))

    counter += 1
    severity = _classify_severity(indicators, "unrelated-resource-access")
    confidence = _classify_confidence(indicators, "unrelated-resource-access")
    risk = _compute_risk_score(indicators, severity, confidence)

    patterns.append(ThreatPattern(
        pattern_id=f"IT-{counter:03d}",
        agent_id=agent,
        pattern_type="unrelated-resource-access",
        severity=severity,
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' accessed resources across {len(resources_by_category)} unrelated categories",
        risk_score=risk,
    ))
    return counter


def _detect_recon_sweep(
    agent: str,
    events: list[dict[str, Any]],
    patterns: list[ThreatPattern],
    counter: int,
) -> int:
    indicators: list[ThreatIndicator] = []
    for ev in events:
        tool = ev.get("actual_tool", ev.get("claimed_tool", ev.get("tool", "")))
        if _is_recon_action(tool):
            indicators.append(ThreatIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("tool_call_id", ev.get("event_id", "")),
                pattern_type="reconnaissance-sweep",
                action=tool,
                resource=ev.get("resource", ""),
                detail=f"Recon action: {tool} on {ev.get('resource', 'unknown')}",
                source_file=ev.get("_source", ""),
                line=ev.get("_line", 0),
            ))

    if len(indicators) < 2:
        return counter

    counter += 1
    severity = _classify_severity(indicators, "reconnaissance-sweep")
    confidence = _classify_confidence(indicators, "reconnaissance-sweep")
    risk = _compute_risk_score(indicators, severity, confidence)

    patterns.append(ThreatPattern(
        pattern_id=f"IT-{counter:03d}",
        agent_id=agent,
        pattern_type="reconnaissance-sweep",
        severity=severity,
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' performed {len(indicators)} reconnaissance/enumeration actions",
        risk_score=risk,
    ))
    return counter


def _load_events(evidence_dir: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    control: list[dict[str, Any]] = []
    for name, target in [("transcripts.jsonl", events), ("control_plane.jsonl", control), ("events.jsonl", events)]:
        p = evidence_dir / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        target.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events, control


def format_text(report: InsiderThreatReport) -> str:
    lines: list[str] = []
    lines.append("Insider Threat Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:         {s.total_patterns}")
    lines.append(f"  Agents flagged:         {s.agents_flagged}")
    if s.highest_risk_agent:
        lines.append(f"  Highest risk agent:     {s.highest_risk_agent} (score: {s.highest_risk_score:.3f})")
    lines.append("")

    if s.by_severity:
        lines.append("  By severity:")
        for sev in ("critical", "high", "medium", "low"):
            if sev in s.by_severity:
                lines.append(f"    {sev}: {s.by_severity[sev]}")
        lines.append("")

    if s.by_type:
        lines.append("  By pattern type:")
        for pt, count in sorted(s.by_type.items()):
            lines.append(f"    {pt}: {count}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity.upper()}] {p.pattern_id}: {p.agent_id}")
        lines.append(f"    Type: {p.pattern_type}")
        lines.append(f"    Risk: {p.risk_score:.3f} | Confidence: {p.confidence}")
        lines.append(f"    {p.description}")
        lines.append(f"    Indicators: {len(p.indicators)}")
        for ind in p.indicators[:5]:
            lines.append(f"      - {ind.timestamp}: {ind.action} [{ind.detail}]")
        if len(p.indicators) > 5:
            lines.append(f"      ... and {len(p.indicators) - 5} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: InsiderThreatReport) -> str:
    data = {
        "patterns": [
            {
                **{k: v for k, v in asdict(p).items() if k != "indicators"},
                "indicators": [asdict(ind) for ind in p.indicators],
            }
            for p in report.patterns
        ],
        "summary": asdict(report.summary),
        "agents_flagged": report.agents_flagged,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
