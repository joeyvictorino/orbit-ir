"""Reconstruct agent sessions from evidence events into readable transcripts."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


_SESSION_GAP = timedelta(minutes=30)

_ANOMALY_TYPES = frozenset({
    "anomaly", "alert", "detection", "violation", "suspicious",
    "unauthorized", "denied", "blocked", "escalation",
})


@dataclass
class TranscriptEntry:
    timestamp: str
    agent_id: str
    action: str
    tool_call_id: str
    resource: str
    effect: str
    is_anomaly: bool
    annotation: str


@dataclass
class SessionTranscript:
    session_id: str
    agent_id: str
    start_time: str
    end_time: str
    event_count: int
    anomaly_count: int
    entries: list[TranscriptEntry] = field(default_factory=list)


@dataclass
class ReplayReport:
    total_sessions: int
    total_events: int
    agents: list[str]
    sessions: list[SessionTranscript] = field(default_factory=list)


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


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
    return None


def _is_anomaly(event: dict[str, Any]) -> bool:
    etype = str(event.get("type", "")).lower()
    if any(a in etype for a in _ANOMALY_TYPES):
        return True
    severity = str(event.get("severity", "")).lower()
    if severity in ("high", "critical"):
        return True
    policy = str(event.get("policy_decision", "")).lower()
    if policy in ("denied", "blocked"):
        return True
    return False


def _annotate(event: dict[str, Any], prev: dict[str, Any] | None,
              nxt: dict[str, Any] | None) -> str:
    parts: list[str] = []
    if _is_anomaly(event):
        etype = event.get("type", "unknown")
        sev = event.get("severity", "")
        if sev:
            parts.append(f"ANOMALY ({sev}): {etype}")
        else:
            parts.append(f"ANOMALY: {etype}")
    policy = event.get("policy_decision", "")
    if policy and policy.lower() in ("denied", "blocked"):
        parts.append(f"policy={policy}")
    if prev:
        prev_action = prev.get("actual_tool", prev.get("tool_name", prev.get("action", "")))
        if prev_action:
            parts.append(f"after {prev_action}")
    if nxt:
        nxt_action = nxt.get("actual_tool", nxt.get("tool_name", nxt.get("action", "")))
        if nxt_action:
            parts.append(f"before {nxt_action}")
    return "; ".join(parts)


def _group_sessions(events: list[dict[str, Any]]) -> dict[str, list[list[dict[str, Any]]]]:
    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", ev.get("agent", "unknown"))
        by_agent[agent].append(ev)

    result: dict[str, list[list[dict[str, Any]]]] = {}
    for agent, agent_events in by_agent.items():
        sorted_events = sorted(agent_events, key=lambda e: e.get("timestamp", ""))
        sessions: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        for ev in sorted_events:
            if not current:
                current.append(ev)
                continue
            prev_ts = _parse_ts(current[-1].get("timestamp", ""))
            cur_ts = _parse_ts(ev.get("timestamp", ""))
            if prev_ts and cur_ts and (cur_ts - prev_ts) > _SESSION_GAP:
                sessions.append(current)
                current = [ev]
            else:
                current.append(ev)
        if current:
            sessions.append(current)
        result[agent] = sessions
    return result


class SessionReplayBuilder:
    def replay(self, evidence_dir: str | Path,
               agent_id: str | None = None) -> ReplayReport:
        path = Path(evidence_dir)
        events = _load_events(path)
        if agent_id:
            events = [e for e in events
                      if e.get("agent_id", e.get("agent", "")) == agent_id]

        grouped = _group_sessions(events)
        all_sessions: list[SessionTranscript] = []
        session_counter = 0

        for agent, agent_sessions in sorted(grouped.items()):
            for sess_events in agent_sessions:
                session_counter += 1
                entries: list[TranscriptEntry] = []
                anomaly_count = 0
                for i, ev in enumerate(sess_events):
                    prev_ev = sess_events[i - 1] if i > 0 else None
                    nxt_ev = sess_events[i + 1] if i < len(sess_events) - 1 else None
                    is_anom = _is_anomaly(ev)
                    if is_anom:
                        anomaly_count += 1
                    action = ev.get("actual_tool",
                                    ev.get("tool_name",
                                           ev.get("action",
                                                  ev.get("type", "unknown"))))
                    entries.append(TranscriptEntry(
                        timestamp=ev.get("timestamp", ""),
                        agent_id=agent,
                        action=action,
                        tool_call_id=ev.get("tool_call_id", ""),
                        resource=ev.get("resource", ev.get("endpoint", "")),
                        effect=ev.get("effect", ev.get("result", "")),
                        is_anomaly=is_anom,
                        annotation=_annotate(ev, prev_ev, nxt_ev),
                    ))

                start = sess_events[0].get("timestamp", "") if sess_events else ""
                end = sess_events[-1].get("timestamp", "") if sess_events else ""
                all_sessions.append(SessionTranscript(
                    session_id=f"session-{session_counter:03d}",
                    agent_id=agent,
                    start_time=start,
                    end_time=end,
                    event_count=len(sess_events),
                    anomaly_count=anomaly_count,
                    entries=entries,
                ))

        agents = sorted(grouped.keys())
        return ReplayReport(
            total_sessions=len(all_sessions),
            total_events=sum(s.event_count for s in all_sessions),
            agents=agents,
            sessions=all_sessions,
        )


def replay_sessions(evidence_dir: str | Path,
                    agent_id: str | None = None) -> ReplayReport:
    return SessionReplayBuilder().replay(evidence_dir, agent_id)


def format_replay_text(report: ReplayReport) -> str:
    lines: list[str] = []
    lines.append(f"Session Replay Report")
    lines.append(f"  Sessions: {report.total_sessions}")
    lines.append(f"  Events:   {report.total_events}")
    lines.append(f"  Agents:   {', '.join(report.agents)}")
    lines.append("")

    for sess in report.sessions:
        lines.append(f"--- {sess.session_id} ({sess.agent_id}) ---")
        lines.append(f"  Time: {sess.start_time} -> {sess.end_time}")
        lines.append(f"  Events: {sess.event_count}, Anomalies: {sess.anomaly_count}")
        lines.append("")
        for entry in sess.entries:
            ts_part = entry.timestamp.split("T")[-1].replace("Z", "") if "T" in entry.timestamp else entry.timestamp
            marker = " [!]" if entry.is_anomaly else ""
            resource_part = f" on {entry.resource}" if entry.resource else ""
            effect_part = f" -> {entry.effect}" if entry.effect else ""
            tcid = f" ({entry.tool_call_id})" if entry.tool_call_id else ""
            lines.append(f"  [{ts_part}] {entry.agent_id}: {entry.action}{tcid}{resource_part}{effect_part}{marker}")
            if entry.annotation:
                lines.append(f"           {entry.annotation}")
        lines.append("")

    return "\n".join(lines)


def format_replay_json(report: ReplayReport) -> str:
    return json.dumps(asdict(report), sort_keys=True, indent=2)
