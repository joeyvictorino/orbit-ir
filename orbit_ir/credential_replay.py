"""Credential replay attack detection for agent evidence.

Detects credential replay attacks: same credential used by different agents,
credentials used after revocation, temporal replay patterns, and credential
usage from unexpected sources.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ReplayEvent:
    """A single detected credential replay event."""
    event_id: str
    credential_id: str
    replay_type: str
    agent_id: str
    timestamp: str
    detail: str
    severity: str
    confidence: float
    original_agent: str
    time_delta_seconds: float


@dataclass
class CredentialProfile:
    """Usage profile for a single credential."""
    credential_id: str
    agents_using: list[str]
    first_seen: str
    last_seen: str
    total_uses: int
    replay_count: int
    revoked: bool


@dataclass
class ReplaySummary:
    total_replays: int
    critical_replays: int
    high_replays: int
    credentials_replayed: int
    agents_involved: int
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class ReplayReport:
    events: list[ReplayEvent]
    credential_profiles: list[CredentialProfile]
    summary: ReplaySummary
    agents_involved: list[str]


def _parse_timestamp(ts: str) -> float:
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", ts)
    if not m:
        return 0.0
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    return y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60 + s


def _detect_cross_agent_replay(
    cred_uses: dict[str, list[dict[str, Any]]],
) -> list[ReplayEvent]:
    events: list[ReplayEvent] = []
    for cred_id, uses in cred_uses.items():
        agents = sorted({u["agent_id"] for u in uses})
        if len(agents) < 2:
            continue
        uses_sorted = sorted(uses, key=lambda u: u.get("timestamp", ""))
        original = uses_sorted[0]["agent_id"]
        for use in uses_sorted[1:]:
            if use["agent_id"] != original:
                delta = _parse_timestamp(use.get("timestamp", "")) - _parse_timestamp(uses_sorted[0].get("timestamp", ""))
                severity = "critical" if delta < 60 else ("high" if delta < 300 else "medium")
                events.append(ReplayEvent(
                    event_id="",
                    credential_id=cred_id,
                    replay_type="cross-agent",
                    agent_id=use["agent_id"],
                    timestamp=use.get("timestamp", ""),
                    detail=f"Credential {cred_id} originally used by {original}, replayed by {use['agent_id']}",
                    severity=severity,
                    confidence=min(0.95, 0.7 + len(agents) * 0.05),
                    original_agent=original,
                    time_delta_seconds=delta,
                ))
    return events


def _detect_post_revocation(
    cred_uses: dict[str, list[dict[str, Any]]],
    revocations: dict[str, str],
) -> list[ReplayEvent]:
    events: list[ReplayEvent] = []
    for cred_id, rev_ts in revocations.items():
        if cred_id not in cred_uses:
            continue
        rev_time = _parse_timestamp(rev_ts)
        for use in cred_uses[cred_id]:
            use_time = _parse_timestamp(use.get("timestamp", ""))
            if use_time > rev_time:
                delta = use_time - rev_time
                events.append(ReplayEvent(
                    event_id="",
                    credential_id=cred_id,
                    replay_type="post-revocation",
                    agent_id=use["agent_id"],
                    timestamp=use.get("timestamp", ""),
                    detail=f"Credential {cred_id} used {delta:.0f}s after revocation",
                    severity="critical",
                    confidence=0.95,
                    original_agent="",
                    time_delta_seconds=delta,
                ))
    return events


def _detect_temporal_replay(
    cred_uses: dict[str, list[dict[str, Any]]],
    gap_threshold: float = 3600.0,
) -> list[ReplayEvent]:
    events: list[ReplayEvent] = []
    for cred_id, uses in cred_uses.items():
        if len(uses) < 2:
            continue
        uses_sorted = sorted(uses, key=lambda u: _parse_timestamp(u.get("timestamp", "")))
        for i in range(1, len(uses_sorted)):
            t_prev = _parse_timestamp(uses_sorted[i - 1].get("timestamp", ""))
            t_curr = _parse_timestamp(uses_sorted[i].get("timestamp", ""))
            gap = t_curr - t_prev
            if gap >= gap_threshold:
                severity = "high" if gap >= gap_threshold * 5 else "medium"
                events.append(ReplayEvent(
                    event_id="",
                    credential_id=cred_id,
                    replay_type="temporal-gap",
                    agent_id=uses_sorted[i]["agent_id"],
                    timestamp=uses_sorted[i].get("timestamp", ""),
                    detail=f"Credential {cred_id} reused after {gap:.0f}s gap",
                    severity=severity,
                    confidence=min(0.8, 0.4 + gap / (gap_threshold * 10)),
                    original_agent=uses_sorted[i - 1]["agent_id"],
                    time_delta_seconds=gap,
                ))
    return events


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
    gap_threshold: float = 3600.0,
) -> ReplayReport:
    if control_events is None:
        control_events = []

    cred_uses: dict[str, list[dict[str, Any]]] = defaultdict(list)
    revocations: dict[str, str] = {}

    for ev in control_events + events:
        cred = ev.get("credential_id", "")
        agent = ev.get("agent_id", "")
        if not cred or not agent:
            continue
        cred_uses[cred].append(ev)
        effect = ev.get("effect", "").lower()
        if "revok" in effect or "invalidat" in effect or "expir" in effect:
            revocations[cred] = ev.get("timestamp", "")

    all_events: list[ReplayEvent] = []
    all_events.extend(_detect_cross_agent_replay(cred_uses))
    all_events.extend(_detect_post_revocation(cred_uses, revocations))
    all_events.extend(_detect_temporal_replay(cred_uses, gap_threshold))

    counter = 0
    for e in all_events:
        counter += 1
        e.event_id = f"CR-{counter:03d}"

    all_events.sort(key=lambda e: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(e.severity, 4))

    profiles: list[CredentialProfile] = []
    for cred_id, uses in sorted(cred_uses.items()):
        agents = sorted({u["agent_id"] for u in uses})
        timestamps = [u.get("timestamp", "") for u in uses]
        ts_sorted = sorted(t for t in timestamps if t)
        replay_count = sum(1 for e in all_events if e.credential_id == cred_id)
        profiles.append(CredentialProfile(
            credential_id=cred_id,
            agents_using=agents,
            first_seen=ts_sorted[0] if ts_sorted else "",
            last_seen=ts_sorted[-1] if ts_sorted else "",
            total_uses=len(uses),
            replay_count=replay_count,
            revoked=cred_id in revocations,
        ))

    sev_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for e in all_events:
        sev_counts[e.severity] += 1
        type_counts[e.replay_type] += 1

    all_agents = sorted({e.agent_id for e in all_events} | {e.original_agent for e in all_events if e.original_agent})

    return ReplayReport(
        events=all_events,
        credential_profiles=profiles,
        summary=ReplaySummary(
            total_replays=len(all_events),
            critical_replays=sev_counts.get("critical", 0),
            high_replays=sev_counts.get("high", 0),
            credentials_replayed=len({e.credential_id for e in all_events}),
            agents_involved=len(all_agents),
            by_type=dict(type_counts),
            by_severity=dict(sev_counts),
        ),
        agents_involved=all_agents,
    )


def format_text(report: ReplayReport) -> str:
    lines: list[str] = []
    lines.append("Credential Replay Analysis")
    lines.append("=" * 62)
    lines.append("")
    s = report.summary
    lines.append(f"  Total replays:          {s.total_replays}")
    lines.append(f"  Critical replays:       {s.critical_replays}")
    lines.append(f"  High severity:          {s.high_replays}")
    lines.append(f"  Credentials replayed:   {s.credentials_replayed}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")
    if s.by_type:
        lines.append("  By type:")
        for t, cnt in sorted(s.by_type.items()):
            lines.append(f"    {t}: {cnt}")
        lines.append("")
    for e in report.events:
        lines.append(f"  [{e.severity.upper()}] {e.event_id}: {e.credential_id}")
        lines.append(f"    Type: {e.replay_type}")
        lines.append(f"    {e.detail}")
        lines.append(f"    Agent: {e.agent_id}, Time delta: {e.time_delta_seconds:.0f}s")
        lines.append(f"    Confidence: {e.confidence:.0%}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: ReplayReport) -> str:
    data = {
        "events": [asdict(e) for e in report.events],
        "credential_profiles": [asdict(p) for p in report.credential_profiles],
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
