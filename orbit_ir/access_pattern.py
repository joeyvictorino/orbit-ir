"""Access-pattern anomaly detection — find unusual access times, frequencies, and sequences."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AccessAnomaly:
    anomaly_type: str
    agent_id: str
    description: str
    score: float
    timestamp: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessPatternReport:
    anomaly_count: int
    anomalies: list[AccessAnomaly]
    agents_analyzed: int
    events_analyzed: int
    overall_risk: str
    hourly_distribution: dict[int, int]


_ADMIN_RESOURCES = {"iam", "rbac", "policy", "role", "permission", "admin", "root", "secret", "credential", "token"}


def _parse_ts(ts_str: str) -> datetime | None:
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events


def _is_admin_resource(resource: str) -> bool:
    lower = resource.lower()
    return any(kw in lower for kw in _ADMIN_RESOURCES)


def analyze(
    evidence_dir: str | Path,
    baseline_hours: tuple[int, int] = (6, 22),
) -> AccessPatternReport:
    events = _load_events(Path(evidence_dir))

    timestamped: list[tuple[datetime, dict[str, Any]]] = []
    for ev in events:
        ts_str = ev.get("timestamp", "")
        if not ts_str:
            continue
        dt = _parse_ts(ts_str)
        if dt:
            timestamped.append((dt, ev))

    if not timestamped:
        return AccessPatternReport(
            anomaly_count=0,
            anomalies=[],
            agents_analyzed=0,
            events_analyzed=0,
            overall_risk="low",
            hourly_distribution={},
        )

    timestamped.sort(key=lambda x: x[0])
    anomalies: list[AccessAnomaly] = []
    agents = set()
    hourly: dict[int, int] = defaultdict(int)

    agent_events: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for dt, ev in timestamped:
        agent = ev.get("agent_id", "unknown")
        agents.add(agent)
        hourly[dt.hour] += 1
        agent_events[agent].append((dt, ev))

    start_hour, end_hour = baseline_hours

    # Check 1: unusual access times
    for agent, evts in agent_events.items():
        for dt, ev in evts:
            if not (start_hour <= dt.hour < end_hour):
                anomalies.append(AccessAnomaly(
                    anomaly_type="off_hours_access",
                    agent_id=agent,
                    description=f"Access at {dt.hour:02d}:00 outside baseline hours ({start_hour}-{end_hour})",
                    score=0.6,
                    timestamp=dt.isoformat(),
                    details={"hour": dt.hour, "tool": ev.get("actual_tool", "")},
                ))

    # Check 2: frequency spikes per agent
    for agent, evts in agent_events.items():
        agent_hourly: Counter[int] = Counter()
        for dt, _ in evts:
            agent_hourly[dt.hour] += 1
        if len(agent_hourly) >= 2:
            avg = sum(agent_hourly.values()) / max(len(agent_hourly), 1)
            for hour, count in agent_hourly.items():
                if avg > 0 and count > 2 * avg and count >= 3:
                    anomalies.append(AccessAnomaly(
                        anomaly_type="frequency_spike",
                        agent_id=agent,
                        description=f"Frequency spike at hour {hour:02d}: {count} events vs {avg:.1f} avg",
                        score=min(1.0, count / (avg * 2)) if avg > 0 else 0.5,
                        timestamp=evts[0][0].isoformat(),
                        details={"hour": hour, "count": count, "average": round(avg, 1)},
                    ))

    # Check 3: admin resource access without prior auth
    for agent, evts in agent_events.items():
        seen_auth = False
        for dt, ev in evts:
            resource = ev.get("resource", "")
            tool = ev.get("actual_tool", "")
            effect = ev.get("effect", "")
            text = f"{tool} {effect}".lower()
            if "auth" in text or "login" in text or "credential" in text:
                seen_auth = True
            if _is_admin_resource(resource) and not seen_auth:
                anomalies.append(AccessAnomaly(
                    anomaly_type="admin_without_auth",
                    agent_id=agent,
                    description=f"Admin resource '{resource}' accessed without prior authentication event",
                    score=0.8,
                    timestamp=dt.isoformat(),
                    details={"resource": resource, "tool": tool},
                ))
                break

    # Check 4: repeated failed access
    for agent, evts in agent_events.items():
        consecutive_fails = 0
        for dt, ev in evts:
            decision = ev.get("policy_decision", "")
            if decision in ("denied", "blocked", "failed"):
                consecutive_fails += 1
                if consecutive_fails >= 3:
                    anomalies.append(AccessAnomaly(
                        anomaly_type="repeated_failures",
                        agent_id=agent,
                        description=f"{consecutive_fails} consecutive access failures",
                        score=min(1.0, consecutive_fails / 5),
                        timestamp=dt.isoformat(),
                        details={"consecutive_failures": consecutive_fails},
                    ))
                    break
            else:
                consecutive_fails = 0

    # Check 5: rapid credential switching
    for agent, evts in agent_events.items():
        recent_creds: list[tuple[datetime, str]] = []
        for dt, ev in evts:
            cred = ev.get("credential_id", "")
            if not cred:
                continue
            recent_creds.append((dt, cred))
            window = [(t, c) for t, c in recent_creds if (dt - t).total_seconds() <= 60]
            recent_creds = window
            unique = set(c for _, c in window)
            if len(unique) >= 3:
                anomalies.append(AccessAnomaly(
                    anomaly_type="rapid_credential_switch",
                    agent_id=agent,
                    description=f"{len(unique)} different credentials used within 60 seconds",
                    score=min(1.0, len(unique) / 4),
                    timestamp=dt.isoformat(),
                    details={"credentials_count": len(unique), "window_seconds": 60},
                ))
                break

    # Deduplicate by (type, agent) keeping highest score
    seen_keys: dict[tuple[str, str], int] = {}
    deduped: list[AccessAnomaly] = []
    for a in anomalies:
        key = (a.anomaly_type, a.agent_id)
        if key in seen_keys:
            idx = seen_keys[key]
            if a.score > deduped[idx].score:
                deduped[idx] = a
        else:
            seen_keys[key] = len(deduped)
            deduped.append(a)

    deduped.sort(key=lambda x: -x.score)

    max_score = max((a.score for a in deduped), default=0)
    if max_score >= 0.8:
        overall = "high"
    elif max_score >= 0.5:
        overall = "medium"
    else:
        overall = "low"

    return AccessPatternReport(
        anomaly_count=len(deduped),
        anomalies=deduped,
        agents_analyzed=len(agents),
        events_analyzed=len(timestamped),
        overall_risk=overall,
        hourly_distribution=dict(sorted(hourly.items())),
    )


def format_text(report: AccessPatternReport) -> str:
    lines = [
        "Access Pattern Analysis",
        "=" * 40,
        f"Events analyzed:    {report.events_analyzed}",
        f"Agents analyzed:    {report.agents_analyzed}",
        f"Anomalies found:    {report.anomaly_count}",
        f"Overall risk:       {report.overall_risk}",
        "",
    ]
    if report.anomalies:
        lines.append("Anomalies")
        lines.append("-" * 30)
        for a in report.anomalies:
            lines.append(f"  [{a.score:.2f}] {a.anomaly_type} — {a.agent_id}")
            lines.append(f"    {a.description}")
            lines.append(f"    at {a.timestamp}")
            lines.append("")

    if report.hourly_distribution:
        lines.append("Hourly Distribution")
        lines.append("-" * 30)
        max_count = max(report.hourly_distribution.values(), default=1)
        for hour in range(24):
            count = report.hourly_distribution.get(hour, 0)
            bar = "#" * int(20 * count / max_count) if max_count > 0 else ""
            lines.append(f"  {hour:02d}:00  {bar} {count}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: AccessPatternReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
