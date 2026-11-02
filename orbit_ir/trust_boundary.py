"""Trust boundary crossing detection for agent incident analysis.

Detects when agents cross trust boundaries—transitioning between
privilege levels, resource domains, or network zones—which indicates
potential boundary violations or lateral movement attempts.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SENSITIVE_RESOURCES = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    ".ssh", ".aws", ".kube", ".docker",
    "credentials", "secrets", "tokens", "keys",
    ".env", "config.json", "kubeconfig",
})

PRIVILEGED_TOOLS = frozenset({
    "execute_command", "run_shell", "bash", "exec",
    "write_file", "delete_file", "modify_config",
    "create_user", "grant_access", "elevate",
    "deploy", "install", "sudo",
})

ZONE_PATTERNS = {
    "internal": ["10.", "172.16.", "192.168.", "localhost", "127.0.0.1"],
    "cloud": ["s3://", "gs://", "az://", "aws", "gcp", "azure"],
    "external": ["http://", "https://", "ftp://"],
    "filesystem": ["/etc/", "/var/", "/home/", "/tmp/", "/opt/"],
    "database": ["db:", "sql:", "mongo:", "redis:", "postgres:"],
}


@dataclass
class TrustZone:
    name: str
    privilege_level: int  # 0=low, 1=standard, 2=elevated, 3=admin
    resources: list[str] = field(default_factory=list)


@dataclass
class BoundaryCrossing:
    crossing_id: str
    agent_id: str
    from_zone: str
    to_zone: str
    from_privilege: int
    to_privilege: int
    timestamp: str
    resource: str
    tool: str
    severity: str  # "critical", "high", "medium", "low"
    description: str


@dataclass
class AgentBoundaryProfile:
    agent_id: str
    zones_accessed: list[str]
    max_privilege: int
    boundary_crossings: int
    escalation_count: int
    risk_score: float


@dataclass
class TrustBoundarySummary:
    total_crossings: int
    unique_agents: int
    zones_involved: int
    escalation_events: int
    by_severity: dict[str, int] = field(default_factory=dict)
    by_zone_pair: dict[str, int] = field(default_factory=dict)
    highest_risk_agent: str = ""
    highest_risk_score: float = 0.0


@dataclass
class TrustBoundaryReport:
    crossings: list[BoundaryCrossing]
    agent_profiles: list[AgentBoundaryProfile]
    summary: TrustBoundarySummary


def analyze_trust_boundaries(events: list[dict[str, Any]]) -> TrustBoundaryReport:
    if not events:
        return TrustBoundaryReport(
            crossings=[],
            agent_profiles=[],
            summary=TrustBoundarySummary(total_crossings=0, unique_agents=0, zones_involved=0, escalation_events=0),
        )

    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    for evts in agent_events.values():
        evts.sort(key=lambda e: e.get("timestamp", ""))

    crossings: list[BoundaryCrossing] = []
    counter = 0

    for agent, evts in sorted(agent_events.items()):
        prev_zone = ""
        prev_priv = 0
        for ev in evts:
            zone = _classify_zone(ev)
            priv = _classify_privilege(ev)

            if prev_zone and zone != prev_zone:
                counter += 1
                is_escalation = priv > prev_priv
                severity = _crossing_severity(prev_zone, zone, prev_priv, priv, ev)

                crossings.append(BoundaryCrossing(
                    crossing_id=f"TB-{counter:03d}",
                    agent_id=agent,
                    from_zone=prev_zone,
                    to_zone=zone,
                    from_privilege=prev_priv,
                    to_privilege=priv,
                    timestamp=ev.get("timestamp", ""),
                    resource=ev.get("resource", ""),
                    tool=ev.get("tool", ev.get("claimed_tool", "")),
                    severity=severity,
                    description=_describe_crossing(agent, prev_zone, zone, prev_priv, priv, is_escalation),
                ))

            prev_zone = zone
            prev_priv = priv

    crossings.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c.severity, 4))

    profiles = _build_profiles(agent_events, crossings)

    sev_counts: dict[str, int] = defaultdict(int)
    zone_pairs: dict[str, int] = defaultdict(int)
    escalation_count = 0
    all_zones: set[str] = set()

    for c in crossings:
        sev_counts[c.severity] += 1
        pair = f"{c.from_zone}->{c.to_zone}"
        zone_pairs[pair] += 1
        all_zones.add(c.from_zone)
        all_zones.add(c.to_zone)
        if c.to_privilege > c.from_privilege:
            escalation_count += 1

    highest_agent = ""
    highest_score = 0.0
    for p in profiles:
        if p.risk_score > highest_score:
            highest_score = p.risk_score
            highest_agent = p.agent_id

    return TrustBoundaryReport(
        crossings=crossings,
        agent_profiles=profiles,
        summary=TrustBoundarySummary(
            total_crossings=len(crossings),
            unique_agents=len(agent_events),
            zones_involved=len(all_zones),
            escalation_events=escalation_count,
            by_severity=dict(sev_counts),
            by_zone_pair=dict(zone_pairs),
            highest_risk_agent=highest_agent,
            highest_risk_score=round(highest_score, 4),
        ),
    )


def _classify_zone(ev: dict[str, Any]) -> str:
    resource = ev.get("resource", "").lower()
    tool = ev.get("tool", ev.get("claimed_tool", "")).lower()

    for zone_name, patterns in ZONE_PATTERNS.items():
        for pat in patterns:
            if pat in resource or pat in tool:
                return zone_name

    if any(s in resource for s in SENSITIVE_RESOURCES):
        return "sensitive"

    return "standard"


def _classify_privilege(ev: dict[str, Any]) -> int:
    tool = ev.get("tool", ev.get("claimed_tool", "")).lower()
    resource = ev.get("resource", "").lower()

    if tool in ("sudo", "elevate", "create_user", "grant_access"):
        return 3
    if tool in PRIVILEGED_TOOLS or any(s in resource for s in SENSITIVE_RESOURCES):
        return 2
    if tool in ("read_file", "list_files", "search", "query"):
        return 0
    return 1


def _crossing_severity(from_zone: str, to_zone: str, from_priv: int, to_priv: int, ev: dict[str, Any]) -> str:
    priv_jump = to_priv - from_priv

    if priv_jump >= 2:
        return "critical"
    if to_zone == "sensitive" and from_zone != "sensitive":
        return "critical"

    if priv_jump >= 1 and to_zone in ("cloud", "database"):
        return "high"
    if from_zone == "standard" and to_zone == "external":
        return "high"

    if priv_jump >= 1:
        return "medium"
    if from_zone != to_zone:
        return "medium"

    return "low"


def _describe_crossing(agent: str, from_z: str, to_z: str, from_p: int, to_p: int, escalation: bool) -> str:
    priv_names = {0: "read-only", 1: "standard", 2: "elevated", 3: "admin"}
    parts = [f"Agent '{agent}' crossed from {from_z} to {to_z}"]
    if escalation:
        parts.append(f"with privilege escalation ({priv_names.get(from_p, '?')} -> {priv_names.get(to_p, '?')})")
    return " ".join(parts)


def _build_profiles(
    agent_events: dict[str, list[dict[str, Any]]],
    crossings: list[BoundaryCrossing],
) -> list[AgentBoundaryProfile]:
    agent_crossings: dict[str, list[BoundaryCrossing]] = defaultdict(list)
    for c in crossings:
        agent_crossings[c.agent_id].append(c)

    profiles: list[AgentBoundaryProfile] = []
    for agent, evts in sorted(agent_events.items()):
        zones = set()
        max_priv = 0
        for ev in evts:
            zones.add(_classify_zone(ev))
            max_priv = max(max_priv, _classify_privilege(ev))

        cx = agent_crossings.get(agent, [])
        esc = sum(1 for c in cx if c.to_privilege > c.from_privilege)

        zone_count = len(zones)
        crossing_count = len(cx)
        risk = _compute_risk(zone_count, crossing_count, esc, max_priv)

        profiles.append(AgentBoundaryProfile(
            agent_id=agent,
            zones_accessed=sorted(zones),
            max_privilege=max_priv,
            boundary_crossings=crossing_count,
            escalation_count=esc,
            risk_score=round(risk, 4),
        ))

    profiles.sort(key=lambda p: -p.risk_score)
    return profiles


def _compute_risk(zone_count: int, crossings: int, escalations: int, max_priv: int) -> float:
    zone_factor = min(zone_count / 5.0, 1.0) * 0.25
    crossing_factor = min(crossings / 10.0, 1.0) * 0.25
    escalation_factor = min(escalations / 3.0, 1.0) * 0.30
    priv_factor = min(max_priv / 3.0, 1.0) * 0.20
    return min(zone_factor + crossing_factor + escalation_factor + priv_factor, 1.0)


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


def format_text(report: TrustBoundaryReport) -> str:
    lines: list[str] = []
    lines.append("Trust Boundary Crossing Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total crossings:        {s.total_crossings}")
    lines.append(f"  Unique agents:          {s.unique_agents}")
    lines.append(f"  Zones involved:         {s.zones_involved}")
    lines.append(f"  Escalation events:      {s.escalation_events}")
    lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sev, count in sorted(s.by_severity.items()):
            lines.append(f"    {sev}: {count}")
        lines.append("")

    if s.by_zone_pair:
        lines.append("  Zone Transitions:")
        for pair, count in sorted(s.by_zone_pair.items(), key=lambda x: -x[1]):
            lines.append(f"    {pair}: {count}")
        lines.append("")

    if report.agent_profiles:
        lines.append("  Agent Risk Profiles:")
        lines.append("  " + "-" * 60)
        for p in report.agent_profiles:
            lines.append(f"    {p.agent_id}: risk={p.risk_score:.3f}, zones={len(p.zones_accessed)}, crossings={p.boundary_crossings}, escalations={p.escalation_count}")
        lines.append("")

    for c in report.crossings:
        lines.append(f"  [{c.severity.upper()}] {c.crossing_id}: {c.from_zone} -> {c.to_zone}")
        lines.append(f"    Agent: {c.agent_id}")
        lines.append(f"    {c.description}")
        if c.resource:
            lines.append(f"    Resource: {c.resource}")
        if c.tool:
            lines.append(f"    Tool: {c.tool}")
        if c.timestamp:
            lines.append(f"    Time: {c.timestamp}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: TrustBoundaryReport) -> str:
    data = {
        "crossings": [asdict(c) for c in report.crossings],
        "agent_profiles": [asdict(p) for p in report.agent_profiles],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
