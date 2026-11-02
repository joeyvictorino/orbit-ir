"""Session hijacking detection for agent evidence.

Analyzes agent evidence for session hijacking patterns — agents stealing
or replaying session tokens, impersonating other agents' sessions, or
manipulating session state.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SESSION_FIELDS = {"session_id", "session_token", "token", "auth_token", "bearer"}

SEQUENTIAL_THRESHOLD = 3


@dataclass
class SessionHijackFinding:
    agent_id: str
    pattern: str
    session_id: str
    timestamp: str
    confidence: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionHijackSummary:
    total_findings: int
    token_reuse: int
    id_prediction: int
    session_fixation: int
    session_replay: int
    concurrent_use: int
    privilege_change: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class SessionHijackReport:
    findings: list[SessionHijackFinding]
    summary: SessionHijackSummary
    agents_involved: list[str]


def _get_session_id(ev: dict[str, Any]) -> str:
    for k in ("session_id", "session_token", "token_id"):
        v = ev.get(k, "")
        if v:
            return str(v)
    return ""


def analyze_session_hijack(events: list[dict[str, Any]]) -> SessionHijackReport:
    events_sorted = sorted(events, key=lambda e: e.get("timestamp", ""))

    findings: list[SessionHijackFinding] = []

    _detect_token_reuse(events_sorted, findings)
    _detect_id_prediction(events_sorted, findings)
    _detect_session_fixation(events_sorted, findings)
    _detect_session_replay(events_sorted, findings)
    _detect_concurrent_use(events_sorted, findings)
    _detect_privilege_change(events_sorted, findings)

    all_agents = sorted({f.agent_id for f in findings})
    conf: dict[str, int] = defaultdict(int)
    pattern_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        conf[f.confidence] += 1
        pattern_counts[f.pattern] += 1

    return SessionHijackReport(
        findings=findings,
        summary=SessionHijackSummary(
            total_findings=len(findings),
            token_reuse=pattern_counts.get("session_token_reuse", 0),
            id_prediction=pattern_counts.get("session_id_prediction", 0),
            session_fixation=pattern_counts.get("session_fixation", 0),
            session_replay=pattern_counts.get("session_replay", 0),
            concurrent_use=pattern_counts.get("session_concurrent_use", 0),
            privilege_change=pattern_counts.get("session_privilege_change", 0),
            agents_involved=len(all_agents),
            by_confidence=dict(conf),
        ),
        agents_involved=all_agents,
    )


def _detect_token_reuse(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    token_agents: dict[str, set[str]] = defaultdict(set)
    token_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        sid = _get_session_id(ev)
        if agent and sid:
            token_agents[sid].add(agent)
            token_events[sid].append(ev)

    for sid, agents in sorted(token_agents.items()):
        if len(agents) > 1:
            evts = token_events[sid]
            ts = evts[-1].get("timestamp", "")
            sorted_agents = sorted(agents)
            findings.append(SessionHijackFinding(
                agent_id=sorted_agents[0],
                pattern="session_token_reuse",
                session_id=sid,
                timestamp=ts,
                confidence="high",
                description=f"Session token '{sid}' used by multiple agents: {', '.join(sorted_agents)}",
                evidence={"agents": sorted_agents, "usage_count": len(evts)},
            ))


def _detect_id_prediction(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    agent_sessions: dict[str, list[str]] = defaultdict(list)
    agent_ts: dict[str, str] = {}

    for ev in events:
        agent = ev.get("agent_id", "")
        sid = _get_session_id(ev)
        if agent and sid and sid not in agent_sessions[agent]:
            agent_sessions[agent].append(sid)
            agent_ts[agent] = ev.get("timestamp", "")

    for agent, sids in sorted(agent_sessions.items()):
        if len(sids) < SEQUENTIAL_THRESHOLD:
            continue
        numeric_ids: list[int] = []
        for s in sids:
            digits = "".join(c for c in s if c.isdigit())
            if digits:
                try:
                    numeric_ids.append(int(digits))
                except ValueError:
                    pass

        if len(numeric_ids) < SEQUENTIAL_THRESHOLD:
            continue

        sequential_count = 0
        for i in range(1, len(numeric_ids)):
            if numeric_ids[i] - numeric_ids[i - 1] in (1, 2):
                sequential_count += 1

        if sequential_count >= SEQUENTIAL_THRESHOLD - 1:
            findings.append(SessionHijackFinding(
                agent_id=agent,
                pattern="session_id_prediction",
                session_id=sids[-1],
                timestamp=agent_ts.get(agent, ""),
                confidence="high",
                description=f"Agent '{agent}' accessed {len(sids)} sessions with sequential/predictable IDs",
                evidence={"session_ids": sids[:5], "sequential_pairs": sequential_count},
            ))


def _detect_session_fixation(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    for ev in events:
        agent = ev.get("agent_id", "")
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        effect = ev.get("effect", "")
        sid = _get_session_id(ev)

        lower_tool = str(tool).lower()
        lower_effect = str(effect).lower()

        if not agent or not sid:
            continue

        is_set = any(k in lower_tool for k in ("set_session", "fix_session", "inject_session", "set_cookie"))
        is_pre_auth = any(k in lower_effect for k in ("pre-auth", "before-auth", "fixation", "session-set"))

        if is_set or is_pre_auth:
            findings.append(SessionHijackFinding(
                agent_id=agent,
                pattern="session_fixation",
                session_id=sid,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' set session ID '{sid}' before authentication (session fixation)",
                evidence={"tool": tool, "effect": effect},
            ))


def _detect_session_replay(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    for ev in events:
        agent = ev.get("agent_id", "")
        effect = ev.get("effect", "")
        status = ev.get("status", ev.get("result", ""))
        sid = _get_session_id(ev)

        lower_effect = str(effect).lower()
        lower_status = str(status).lower()

        if not agent or not sid:
            continue

        expired = any(k in lower_effect + lower_status for k in ("expired", "revoked", "invalid-token", "token-expired"))
        reused = any(k in lower_effect for k in ("replay", "reuse", "re-use"))

        if expired or reused:
            findings.append(SessionHijackFinding(
                agent_id=agent,
                pattern="session_replay",
                session_id=sid,
                timestamp=ev.get("timestamp", ""),
                confidence="high" if reused else "medium",
                description=f"Agent '{agent}' used expired/revoked session token '{sid}'",
                evidence={"effect": effect, "status": str(status)},
            ))


def _detect_concurrent_use(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    session_locations: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    session_ts: dict[str, str] = {}

    for ev in events:
        agent = ev.get("agent_id", "")
        sid = _get_session_id(ev)
        location = ev.get("location", ev.get("source_ip", ev.get("origin", "")))
        if agent and sid and location:
            session_locations[sid][agent].add(location)
            session_ts[sid] = ev.get("timestamp", "")

    for sid, agent_locs in sorted(session_locations.items()):
        for agent, locs in sorted(agent_locs.items()):
            if len(locs) > 1:
                sorted_locs = sorted(locs)
                findings.append(SessionHijackFinding(
                    agent_id=agent,
                    pattern="session_concurrent_use",
                    session_id=sid,
                    timestamp=session_ts.get(sid, ""),
                    confidence="high",
                    description=f"Session '{sid}' used by agent '{agent}' from {len(locs)} locations: {', '.join(sorted_locs)}",
                    evidence={"locations": sorted_locs},
                ))


def _detect_privilege_change(
    events: list[dict[str, Any]],
    findings: list[SessionHijackFinding],
) -> None:
    session_roles: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        sid = _get_session_id(ev)
        role = ev.get("role", ev.get("privilege", ""))
        ts = ev.get("timestamp", "")
        if agent and sid and role:
            session_roles[sid].append((agent, role, ts))

    elevated = {"admin", "root", "superuser", "owner", "elevated", "privileged"}

    for sid, entries in sorted(session_roles.items()):
        if len(entries) < 2:
            continue
        roles_seen: list[str] = []
        for _, role, _ in entries:
            if role not in roles_seen:
                roles_seen.append(role)

        if len(roles_seen) < 2:
            continue

        initial = roles_seen[0]
        final = roles_seen[-1]
        agent = entries[-1][0]
        ts = entries[-1][2]

        has_auth = any(
            any(k in str(ev.get("effect", "")).lower() for k in ("re-auth", "reauth", "mfa", "challenge"))
            for ev in []
        )

        if final.lower() in elevated and initial.lower() not in elevated and not has_auth:
            findings.append(SessionHijackFinding(
                agent_id=agent,
                pattern="session_privilege_change",
                session_id=sid,
                timestamp=ts,
                confidence="high",
                description=f"Session '{sid}' privileges escalated from '{initial}' to '{final}' without re-authentication",
                evidence={"initial_role": initial, "final_role": final, "roles_seen": roles_seen},
            ))


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
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


def format_text(report: SessionHijackReport) -> str:
    lines: list[str] = []
    lines.append("Session Hijacking Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total findings:         {s.total_findings}")
    lines.append(f"  Token reuse:            {s.token_reuse}")
    lines.append(f"  ID prediction:          {s.id_prediction}")
    lines.append(f"  Session fixation:       {s.session_fixation}")
    lines.append(f"  Session replay:         {s.session_replay}")
    lines.append(f"  Concurrent use:         {s.concurrent_use}")
    lines.append(f"  Privilege change:       {s.privilege_change}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if report.findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 58)
        for f in report.findings:
            lines.append(f"    [{f.confidence.upper()}] {f.pattern}: {f.agent_id}")
            lines.append(f"      {f.description}")
            lines.append(f"      Session: {f.session_id}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: SessionHijackReport) -> str:
    data = {
        "findings": [asdict(f) for f in report.findings],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
