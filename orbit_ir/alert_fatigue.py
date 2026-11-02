"""Alert-fatigue detection for incident response evidence.

Identifies redundant, duplicate, and low-signal alerts that contribute
to analyst fatigue — repeated alerts from the same agent/rule/source,
alert storms (many alerts in short windows), and suppressed-but-recurring
patterns that may mask real threats beneath noise.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class AlertRecord:
    agent_id: str
    event_id: str
    timestamp: str
    alert_type: str
    severity: str
    message: str
    source: str


@dataclass
class DuplicateCluster:
    canonical_message: str
    alert_type: str
    count: int
    agent_ids: list[str]
    first_seen: str
    last_seen: str
    event_ids: list[str]


@dataclass
class AlertStorm:
    start_time: str
    end_time: str
    alert_count: int
    unique_types: int
    agent_ids: list[str]
    description: str


@dataclass
class FatigueAnomaly:
    anomaly_type: str
    severity: str
    description: str
    affected_agents: list[str]
    alert_count: int


@dataclass
class AgentAlertProfile:
    agent_id: str
    total_alerts: int
    unique_types: int
    duplicate_rate: float
    most_common_type: str
    most_common_count: int


@dataclass
class AlertFatigueSummary:
    total_agents: int
    total_alerts: int
    unique_alert_types: int
    duplicate_clusters: int
    total_duplicates: int
    alert_storms: int
    fatigue_score: int
    most_noisy_agent: str
    most_common_alert: str


@dataclass
class AlertFatigueReport:
    alerts: list[AlertRecord]
    clusters: list[DuplicateCluster]
    storms: list[AlertStorm]
    anomalies: list[FatigueAnomaly]
    profiles: list[AgentAlertProfile]
    summary: AlertFatigueSummary
    agents_involved: list[str]


_SEVERITY_WORDS = re.compile(
    r"(?i)\b(critical|high|medium|low|info|informational|warning|error|alert)\b"
)

_ALERT_TYPE_PATTERNS = {
    "authentication": re.compile(r"(?i)\b(auth|login|credential|password|token|session)\b"),
    "access-violation": re.compile(r"(?i)\b(denied|forbidden|unauthorized|403|401|permission)\b"),
    "anomaly": re.compile(r"(?i)\b(anomal|unusual|unexpected|abnormal|outlier)\b"),
    "resource": re.compile(r"(?i)\b(cpu|memory|disk|quota|limit|threshold|capacity)\b"),
    "network": re.compile(r"(?i)\b(connection|timeout|refused|dns|port|socket|network)\b"),
    "security": re.compile(r"(?i)\b(attack|exploit|injection|malicious|threat|vuln)\b"),
}


def _classify_alert_type(message: str) -> str:
    for atype, pattern in _ALERT_TYPE_PATTERNS.items():
        if pattern.search(message):
            return atype
    return "general"


def _extract_severity(message: str) -> str:
    m = _SEVERITY_WORDS.search(message)
    if m:
        word = m.group(1).lower()
        if word in ("critical",):
            return "critical"
        if word in ("high", "error"):
            return "high"
        if word in ("medium", "warning"):
            return "medium"
        if word in ("low", "info", "informational", "alert"):
            return "low"
    return "medium"


def _normalize_message(msg: str) -> str:
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<ID>", msg)
    msg = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", msg)
    msg = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^ ]*", "<TS>", msg)
    msg = re.sub(r"\b\d{4,}\b", "<NUM>", msg)
    return msg.strip()


def _extract_alerts(events: list[dict[str, Any]]) -> list[AlertRecord]:
    alerts: list[AlertRecord] = []
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        msg = ev.get("alert", ev.get("message", ev.get("content", "")))
        if not msg or not isinstance(msg, str):
            continue
        sev = ev.get("severity", _extract_severity(msg))
        atype = ev.get("alert_type", _classify_alert_type(msg))
        source = ev.get("source", ev.get("rule_id", "unknown"))

        alerts.append(AlertRecord(
            agent_id=agent,
            event_id=ev.get("event_id", ""),
            timestamp=ev.get("timestamp", ""),
            alert_type=atype,
            severity=sev if isinstance(sev, str) else "medium",
            message=msg[:300],
            source=source if isinstance(source, str) else "unknown",
        ))

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def _find_duplicates(alerts: list[AlertRecord]) -> list[DuplicateCluster]:
    buckets: dict[str, list[AlertRecord]] = defaultdict(list)
    for a in alerts:
        key = _normalize_message(a.message)
        buckets[key].append(a)

    clusters: list[DuplicateCluster] = []
    for norm_msg, group in sorted(buckets.items(), key=lambda x: -len(x[1])):
        if len(group) < 2:
            continue
        agents = sorted(set(a.agent_id for a in group))
        clusters.append(DuplicateCluster(
            canonical_message=norm_msg[:200],
            alert_type=group[0].alert_type,
            count=len(group),
            agent_ids=agents,
            first_seen=group[0].timestamp,
            last_seen=group[-1].timestamp,
            event_ids=[a.event_id for a in group],
        ))

    clusters.sort(key=lambda c: -c.count)
    return clusters


def _detect_storms(alerts: list[AlertRecord], window_size: int = 10) -> list[AlertStorm]:
    if len(alerts) < window_size:
        return []

    storms: list[AlertStorm] = []
    i = 0
    while i <= len(alerts) - window_size:
        window = alerts[i:i + window_size]
        types_in_window = set(a.alert_type for a in window)
        agents_in_window = sorted(set(a.agent_id for a in window))

        if len(types_in_window) >= 3 or window_size >= 10:
            end = i + window_size
            while end < len(alerts) and end < i + window_size * 3:
                end += 1

            storm_alerts = alerts[i:end]
            storms.append(AlertStorm(
                start_time=storm_alerts[0].timestamp,
                end_time=storm_alerts[-1].timestamp,
                alert_count=len(storm_alerts),
                unique_types=len(set(a.alert_type for a in storm_alerts)),
                agent_ids=sorted(set(a.agent_id for a in storm_alerts)),
                description=(
                    f"Alert storm: {len(storm_alerts)} alerts across "
                    f"{len(set(a.agent_id for a in storm_alerts))} agents"
                ),
            ))
            i = end
        else:
            i += 1

    return storms


def _build_anomalies(
    clusters: list[DuplicateCluster],
    storms: list[AlertStorm],
    alerts: list[AlertRecord],
) -> list[FatigueAnomaly]:
    anomalies: list[FatigueAnomaly] = []

    for cluster in clusters:
        if cluster.count >= 10:
            anomalies.append(FatigueAnomaly(
                anomaly_type="high-duplicate-rate",
                severity="high",
                description=(
                    f"Alert '{cluster.canonical_message[:80]}' repeated "
                    f"{cluster.count} times — severe noise source"
                ),
                affected_agents=cluster.agent_ids,
                alert_count=cluster.count,
            ))
        elif cluster.count >= 5:
            anomalies.append(FatigueAnomaly(
                anomaly_type="duplicate-cluster",
                severity="medium",
                description=(
                    f"Alert '{cluster.canonical_message[:80]}' repeated "
                    f"{cluster.count} times"
                ),
                affected_agents=cluster.agent_ids,
                alert_count=cluster.count,
            ))

    for storm in storms:
        anomalies.append(FatigueAnomaly(
            anomaly_type="alert-storm",
            severity="high",
            description=storm.description,
            affected_agents=storm.agent_ids,
            alert_count=storm.alert_count,
        ))

    agent_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        agent_counts[a.agent_id] += 1
    avg_count = sum(agent_counts.values()) / max(len(agent_counts), 1)
    for agent, count in agent_counts.items():
        if avg_count > 0 and count > avg_count * 3 and count >= 10:
            anomalies.append(FatigueAnomaly(
                anomaly_type="noisy-agent",
                severity="medium",
                description=(
                    f"Agent '{agent}' generated {count} alerts, "
                    f"{count / avg_count:.1f}x the average"
                ),
                affected_agents=[agent],
                alert_count=count,
            ))

    anomalies.sort(key=lambda a: {"high": 0, "medium": 1, "low": 2}.get(a.severity, 3))
    return anomalies


def _build_profiles(alerts: list[AlertRecord]) -> list[AgentAlertProfile]:
    agent_alerts: dict[str, list[AlertRecord]] = defaultdict(list)
    for a in alerts:
        agent_alerts[a.agent_id].append(a)

    profiles: list[AgentAlertProfile] = []
    for agent in sorted(agent_alerts):
        aa = agent_alerts[agent]
        type_counts: dict[str, int] = defaultdict(int)
        for a in aa:
            type_counts[a.alert_type] += 1

        most_common = max(type_counts, key=type_counts.get)  # type: ignore[arg-type]
        norm_counts: dict[str, int] = defaultdict(int)
        for a in aa:
            norm_counts[_normalize_message(a.message)] += 1
        dup_count = sum(c - 1 for c in norm_counts.values() if c > 1)

        profiles.append(AgentAlertProfile(
            agent_id=agent,
            total_alerts=len(aa),
            unique_types=len(type_counts),
            duplicate_rate=round(dup_count / max(len(aa), 1), 3),
            most_common_type=most_common,
            most_common_count=type_counts[most_common],
        ))

    return profiles


def analyze_alert_fatigue(events: list[dict[str, Any]]) -> AlertFatigueReport:
    alerts = _extract_alerts(events)

    if not alerts:
        return AlertFatigueReport(
            alerts=[],
            clusters=[],
            storms=[],
            anomalies=[],
            profiles=[],
            summary=AlertFatigueSummary(
                total_agents=0,
                total_alerts=0,
                unique_alert_types=0,
                duplicate_clusters=0,
                total_duplicates=0,
                alert_storms=0,
                fatigue_score=0,
                most_noisy_agent="",
                most_common_alert="",
            ),
            agents_involved=[],
        )

    clusters = _find_duplicates(alerts)
    storms = _detect_storms(alerts)
    anomalies = _build_anomalies(clusters, storms, alerts)
    profiles = _build_profiles(alerts)

    total_duplicates = sum(c.count - 1 for c in clusters)
    all_types = set(a.alert_type for a in alerts)
    type_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        type_counts[a.alert_type] += 1
    most_common_alert = max(type_counts, key=type_counts.get) if type_counts else ""  # type: ignore[arg-type]

    agent_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        agent_counts[a.agent_id] += 1
    most_noisy = max(agent_counts, key=agent_counts.get) if agent_counts else ""  # type: ignore[arg-type]

    dup_ratio = total_duplicates / max(len(alerts), 1)
    storm_ratio = len(storms) / max(len(alerts) / 10, 1)
    fatigue_score = max(0, min(100, int(100 - dup_ratio * 60 - storm_ratio * 20 - len(anomalies) * 5)))

    agents_involved = sorted(set(a.agent_id for a in alerts))

    return AlertFatigueReport(
        alerts=alerts,
        clusters=clusters,
        storms=storms,
        anomalies=anomalies,
        profiles=profiles,
        summary=AlertFatigueSummary(
            total_agents=len(agents_involved),
            total_alerts=len(alerts),
            unique_alert_types=len(all_types),
            duplicate_clusters=len(clusters),
            total_duplicates=total_duplicates,
            alert_storms=len(storms),
            fatigue_score=fatigue_score,
            most_noisy_agent=most_noisy,
            most_common_alert=most_common_alert,
        ),
        agents_involved=agents_involved,
    )


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    for name in ("alerts.jsonl", "events.jsonl", "findings.jsonl"):
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


def format_text(report: AlertFatigueReport) -> str:
    lines: list[str] = []
    lines.append("Alert Fatigue Analysis Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total agents:          {s.total_agents}")
    lines.append(f"  Total alerts:          {s.total_alerts}")
    lines.append(f"  Unique alert types:    {s.unique_alert_types}")
    lines.append(f"  Duplicate clusters:    {s.duplicate_clusters}")
    lines.append(f"  Total duplicates:      {s.total_duplicates}")
    lines.append(f"  Alert storms:          {s.alert_storms}")
    lines.append(f"  Fatigue score:         {s.fatigue_score}/100")
    if s.most_noisy_agent:
        lines.append(f"  Most noisy agent:      {s.most_noisy_agent}")
    if s.most_common_alert:
        lines.append(f"  Most common alert:     {s.most_common_alert}")
    lines.append("")

    if report.profiles:
        lines.append("  Agent Alert Profiles:")
        lines.append("  " + "-" * 60)
        for p in sorted(report.profiles, key=lambda x: x.total_alerts, reverse=True):
            lines.append(
                f"    {p.agent_id}: {p.total_alerts} alerts, "
                f"{p.unique_types} types, "
                f"{p.duplicate_rate:.0%} duplicates"
            )
        lines.append("")

    if report.clusters:
        lines.append("  Duplicate Clusters:")
        lines.append("  " + "-" * 60)
        for c in report.clusters[:10]:
            lines.append(f"    [{c.count}x] {c.alert_type}: {c.canonical_message[:60]}")
        lines.append("")

    if report.anomalies:
        lines.append("  Fatigue Anomalies:")
        lines.append("  " + "-" * 60)
        for a in report.anomalies:
            lines.append(f"    [{a.severity.upper()}] {a.anomaly_type}: {a.description[:70]}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AlertFatigueReport) -> str:
    data = {
        "clusters": [
            {
                "canonical_message": c.canonical_message,
                "alert_type": c.alert_type,
                "count": c.count,
                "agent_ids": c.agent_ids,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
            }
            for c in report.clusters
        ],
        "storms": [asdict(s) for s in report.storms],
        "anomalies": [asdict(a) for a in report.anomalies],
        "profiles": [asdict(p) for p in report.profiles],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
