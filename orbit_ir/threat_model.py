"""STRIDE threat model builder from agent incident evidence.

Analyzes evidence to identify threats in each STRIDE category
(Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) and maps them to
observed agent behaviors.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


STRIDE_CATEGORIES = {
    "spoofing": "Identity spoofing: agent impersonating another agent or user",
    "tampering": "Data tampering: unauthorized modification of data or configuration",
    "repudiation": "Repudiation: actions without audit trail or deniable activity",
    "info_disclosure": "Information disclosure: unauthorized data access or leakage",
    "denial_of_service": "Denial of service: resource exhaustion or blocking patterns",
    "elevation": "Elevation of privilege: gaining unauthorized capabilities",
}

THREAT_SIGNALS = {
    "spoofing": [
        ("agent_id_change", "Agent changed identity mid-session"),
        ("impersonation", "Agent used another agent's credentials or identity"),
        ("forged_auth", "Forged or replayed authentication tokens"),
    ],
    "tampering": [
        ("config_modify", "Modified system configuration files"),
        ("data_alter", "Altered data without authorization"),
        ("log_modify", "Modified or deleted log entries"),
        ("tool_param_inject", "Injected parameters into tool calls"),
    ],
    "repudiation": [
        ("no_audit_trail", "Actions performed without audit logging"),
        ("timestamp_gap", "Gaps in event timestamps suggesting deleted records"),
        ("unsigned_action", "Critical actions without cryptographic signing"),
    ],
    "info_disclosure": [
        ("data_exfil", "Data read from sensitive paths or APIs"),
        ("credential_access", "Access to credential stores or secrets"),
        ("env_leak", "Environment variable or configuration leakage"),
        ("excessive_read", "Broad file system or API read patterns"),
    ],
    "denial_of_service": [
        ("resource_exhaust", "Resource exhaustion patterns (CPU, memory, disk)"),
        ("rapid_retry", "Rapid retry loops without backoff"),
        ("flood", "High-volume request patterns"),
        ("deadlock", "Potential deadlock or blocking sequences"),
    ],
    "elevation": [
        ("priv_escalate", "Privilege escalation attempts"),
        ("cap_add", "Capability addition or security context changes"),
        ("role_change", "Unauthorized role or permission changes"),
        ("sandbox_escape", "Container or sandbox escape attempts"),
    ],
}


@dataclass
class Threat:
    category: str
    signal: str
    description: str
    agent_id: str
    evidence_count: int
    severity: str  # critical, high, medium, low
    sample_events: list[str] = field(default_factory=list)


@dataclass
class CategorySummary:
    category: str
    description: str
    threat_count: int
    top_severity: str
    agents_involved: list[str] = field(default_factory=list)


@dataclass
class ThreatModelReport:
    threats: list[Threat] = field(default_factory=list)
    categories: list[CategorySummary] = field(default_factory=list)
    summary: ThreatModelSummary = field(default_factory=lambda: ThreatModelSummary())


@dataclass
class ThreatModelSummary:
    total_threats: int = 0
    total_agents: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    highest_risk_category: str = ""


def analyze(evidence_dir: Path) -> ThreatModelReport:
    events = _load_events(evidence_dir)
    if not events:
        return ThreatModelReport()

    agent_events: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        aid = ev.get("agent_id", ev.get("agent", "unknown"))
        agent_events[str(aid)].append(ev)

    threats: list[Threat] = []
    for agent_id, evs in agent_events.items():
        threats.extend(_detect_threats(agent_id, evs))

    threats.sort(key=lambda t: _severity_rank(t.severity), reverse=True)

    cat_map: dict[str, list[Threat]] = defaultdict(list)
    for t in threats:
        cat_map[t.category].append(t)

    categories: list[CategorySummary] = []
    for cat in STRIDE_CATEGORIES:
        ct = cat_map.get(cat, [])
        if ct:
            agents = sorted(set(t.agent_id for t in ct))
            top_sev = max(ct, key=lambda t: _severity_rank(t.severity)).severity
            categories.append(CategorySummary(
                category=cat,
                description=STRIDE_CATEGORIES[cat],
                threat_count=len(ct),
                top_severity=top_sev,
                agents_involved=agents,
            ))

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = defaultdict(int)
    for t in threats:
        by_category[t.category] = by_category.get(t.category, 0) + 1
        by_severity[t.severity] += 1

    highest = ""
    if by_category:
        highest = max(by_category, key=by_category.get)  # type: ignore[arg-type]

    return ThreatModelReport(
        threats=threats,
        categories=categories,
        summary=ThreatModelSummary(
            total_threats=len(threats),
            total_agents=len(agent_events),
            by_category=by_category,
            by_severity=dict(by_severity),
            highest_risk_category=highest,
        ),
    )


def _detect_threats(agent_id: str, events: list[dict]) -> list[Threat]:
    threats: list[Threat] = []

    action_types = [str(e.get("action", e.get("type", ""))) for e in events]
    tool_names = [str(e.get("tool", "")) for e in events]
    resources = [str(e.get("resource", e.get("path", ""))) for e in events]

    # Spoofing: identity changes
    ids_used = set()
    for e in events:
        for k in ("agent_id", "agent", "user", "identity"):
            if k in e:
                ids_used.add(str(e[k]))
    if len(ids_used) > 1:
        threats.append(Threat(
            category="spoofing",
            signal="agent_id_change",
            description="Agent used multiple identities",
            agent_id=agent_id,
            evidence_count=len(ids_used),
            severity="high",
            sample_events=[f"identities: {', '.join(sorted(ids_used))}"],
        ))

    # Tampering: config/data modification
    write_actions = [a for a in action_types if any(w in a.lower() for w in ("write", "modify", "update", "delete", "create", "put"))]
    config_writes = [r for r in resources if any(p in r.lower() for p in ("config", ".env", ".yaml", ".yml", ".json", ".toml", "settings"))]
    if config_writes:
        threats.append(Threat(
            category="tampering",
            signal="config_modify",
            description="Modified configuration files",
            agent_id=agent_id,
            evidence_count=len(config_writes),
            severity="high",
            sample_events=config_writes[:3],
        ))

    # Tampering: tool parameter injection
    injections = [e for e in events if _has_injection_pattern(e)]
    if injections:
        threats.append(Threat(
            category="tampering",
            signal="tool_param_inject",
            description="Suspicious parameters in tool calls",
            agent_id=agent_id,
            evidence_count=len(injections),
            severity="critical",
            sample_events=[str(e.get("tool", ""))[:80] for e in injections[:3]],
        ))

    # Repudiation: gaps in timeline
    timestamps = sorted(e.get("timestamp", "") for e in events if e.get("timestamp"))
    if len(timestamps) >= 3:
        gaps = _find_timeline_gaps(timestamps)
        if gaps > 0:
            threats.append(Threat(
                category="repudiation",
                signal="timestamp_gap",
                description=f"Found {gaps} suspicious gaps in event timeline",
                agent_id=agent_id,
                evidence_count=gaps,
                severity="medium",
            ))

    # Info disclosure: broad reads
    read_actions = [a for a in action_types if any(r in a.lower() for r in ("read", "get", "list", "fetch", "download"))]
    sensitive_reads = [r for r in resources if any(s in r.lower() for s in ("secret", "credential", "password", "key", "token", ".env", "private"))]
    if sensitive_reads:
        threats.append(Threat(
            category="info_disclosure",
            signal="credential_access",
            description="Accessed sensitive resources",
            agent_id=agent_id,
            evidence_count=len(sensitive_reads),
            severity="critical",
            sample_events=sensitive_reads[:3],
        ))
    elif len(set(resources)) > 20:
        threats.append(Threat(
            category="info_disclosure",
            signal="excessive_read",
            description=f"Broad resource access pattern ({len(set(resources))} unique resources)",
            agent_id=agent_id,
            evidence_count=len(set(resources)),
            severity="medium",
        ))

    # Denial of service: rapid patterns
    if len(events) > 50:
        timestamps_list = [e.get("timestamp", "") for e in events if e.get("timestamp")]
        if _has_rapid_pattern(timestamps_list):
            threats.append(Threat(
                category="denial_of_service",
                signal="rapid_retry",
                description="Rapid event pattern detected",
                agent_id=agent_id,
                evidence_count=len(events),
                severity="medium",
            ))

    # Elevation: privilege-related actions
    priv_actions = [e for e in events if any(p in str(e).lower() for p in (
        "sudo", "root", "admin", "privilege", "escalat", "capability", "securitycontext",
        "chmod", "chown", "setuid",
    ))]
    if priv_actions:
        threats.append(Threat(
            category="elevation",
            signal="priv_escalate",
            description="Privilege escalation indicators",
            agent_id=agent_id,
            evidence_count=len(priv_actions),
            severity="critical",
            sample_events=[str(e.get("action", e.get("type", "")))[:80] for e in priv_actions[:3]],
        ))

    return threats


def _has_injection_pattern(event: dict) -> bool:
    params = str(event.get("parameters", event.get("args", event.get("input", ""))))
    injection_markers = ("&&", "||", ";", "`", "$(", "${", "../", "\\n", "%0a")
    return any(m in params for m in injection_markers)


def _find_timeline_gaps(timestamps: list[str]) -> int:
    if len(timestamps) < 3:
        return 0
    gaps = 0
    try:
        from datetime import datetime
        dts = []
        for ts in timestamps:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
                try:
                    dts.append(datetime.strptime(ts[:26], fmt))
                    break
                except ValueError:
                    pass

        if len(dts) >= 3:
            deltas = [(dts[i+1] - dts[i]).total_seconds() for i in range(len(dts)-1)]
            if deltas:
                avg = sum(deltas) / len(deltas)
                if avg > 0:
                    gaps = sum(1 for d in deltas if d > avg * 10)
    except Exception:
        pass
    return gaps


def _has_rapid_pattern(timestamps: list[str]) -> bool:
    if len(timestamps) < 10:
        return False
    try:
        from datetime import datetime
        dts = []
        for ts in timestamps[:50]:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    dts.append(datetime.strptime(ts[:26], fmt))
                    break
                except ValueError:
                    pass
        if len(dts) >= 10:
            deltas = [(dts[i+1] - dts[i]).total_seconds() for i in range(len(dts)-1)]
            sub_second = sum(1 for d in deltas if 0 <= d < 0.1)
            return sub_second > len(deltas) * 0.5
    except Exception:
        pass
    return False


def _severity_rank(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)


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


def format_text(report: ThreatModelReport) -> str:
    lines: list[str] = []
    lines.append("STRIDE Threat Model Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total threats: {s.total_threats}")
    lines.append(f"  Agents analyzed: {s.total_agents}")
    if s.highest_risk_category:
        lines.append(f"  Highest risk category: {s.highest_risk_category}")
    lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sev in ("critical", "high", "medium", "low"):
            if sev in s.by_severity:
                lines.append(f"    {sev}: {s.by_severity[sev]}")
        lines.append("")

    for cat in report.categories:
        lines.append(f"  [{cat.top_severity.upper()}] {cat.category} ({cat.threat_count} threats)")
        lines.append(f"    {cat.description}")
        lines.append(f"    Agents: {', '.join(cat.agents_involved)}")
        lines.append("")

    if report.threats:
        lines.append("  Threat Details:")
        lines.append("  " + "-" * 58)
        for t in report.threats:
            lines.append(f"  [{t.severity.upper()}] {t.category}/{t.signal}")
            lines.append(f"    Agent: {t.agent_id}")
            lines.append(f"    {t.description}")
            lines.append(f"    Evidence count: {t.evidence_count}")
            if t.sample_events:
                for sample in t.sample_events[:2]:
                    lines.append(f"      - {sample}")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ThreatModelReport) -> str:
    data = {
        "threats": [asdict(t) for t in report.threats],
        "categories": [asdict(c) for c in report.categories],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
