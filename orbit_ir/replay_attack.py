"""Replay attack detection in agent evidence.

Identifies patterns where agents or external actors replay previously
observed actions, tool calls, or message sequences to bypass security
controls, re-execute privileged operations, or exploit time-of-check
to time-of-use (TOCTOU) windows.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ACTION_REPLAY_KEYWORDS = {
    "replay", "replayed", "re-execute", "resubmit", "resend",
    "duplicate request", "duplicate action", "repeated call",
    "same request", "identical request", "retry attack",
}

TOCTOU_KEYWORDS = {
    "toctou", "time of check", "race condition", "check then use",
    "stale token", "expired session", "reuse token", "replay token",
    "nonce reuse", "nonce replay",
}

SEQUENCE_REPLAY_KEYWORDS = {
    "sequence replay", "conversation replay", "message replay",
    "session replay", "history replay", "context replay",
    "inject history", "fabricate history", "fake context",
}

CREDENTIAL_REPLAY_KEYWORDS = {
    "credential replay", "token replay", "session hijack",
    "cookie replay", "auth replay", "bearer replay",
    "stolen session", "cloned session", "forged token",
}

IDEMPOTENCY_KEYWORDS = {
    "idempotency", "idempotent", "duplicate detection",
    "request id", "transaction id", "dedup", "deduplication",
    "at-most-once", "exactly-once",
}

REPLAY_ATTACK_TYPES = {
    "action-replay",
    "toctou",
    "sequence-replay",
    "credential-replay",
    "idempotency-bypass",
}


@dataclass
class ReplayAttackPattern:
    timestamp: str
    agent_id: str
    event_id: str
    replay_type: str
    evidence: str
    target_action: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class ReplayAttackSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    actions_targeted: int = 0


@dataclass
class ReplayAttackReport:
    patterns: list[ReplayAttackPattern]
    summary: ReplayAttackSummary
    agents_involved: list[str]
    replay_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_action_replay(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, ACTION_REPLAY_KEYWORDS)
    if matches:
        return True, matches, f"Action replay: {', '.join(matches)}"
    return False, [], ""


def _detect_toctou(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    error = event.get("error", "")
    full_text = content + " " + error
    matches = _match_keywords(full_text, TOCTOU_KEYWORDS)
    if matches:
        return True, matches, f"TOCTOU vulnerability: {', '.join(matches)}"
    return False, [], ""


def _detect_sequence_replay(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, SEQUENCE_REPLAY_KEYWORDS)
    if matches:
        return True, matches, f"Sequence replay: {', '.join(matches)}"
    return False, [], ""


def _detect_credential_replay(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, CREDENTIAL_REPLAY_KEYWORDS)
    if matches:
        return True, matches, f"Credential replay: {', '.join(matches)}"
    return False, [], ""


def _detect_idempotency_bypass(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, IDEMPOTENCY_KEYWORDS)
    if matches:
        return True, matches, f"Idempotency bypass: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(replay_type: str, matches: list[str]) -> str:
    if replay_type in ("credential-replay", "toctou"):
        return "critical" if len(matches) >= 2 else "high"
    if replay_type == "sequence-replay":
        return "high"
    if len(matches) >= 3:
        return "high"
    return "medium"


def _load_events(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    events: list[dict[str, Any]] = []
    if not p.exists():
        return events
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def _detect_replay_chains(patterns: list[ReplayAttackPattern]) -> list[dict[str, Any]]:
    agent_types: dict[str, set[str]] = defaultdict(set)
    for p in patterns:
        if p.agent_id:
            agent_types[p.agent_id].add(p.replay_type)

    chains: list[dict[str, Any]] = []
    for agent, types in agent_types.items():
        if ("credential-replay" in types or "toctou" in types) and \
           ("action-replay" in types or "sequence-replay" in types):
            chains.append({
                "agent": agent,
                "types": sorted(types),
                "severity": "critical",
                "description": f"Agent '{agent}' combines credential/timing attack with action replay",
            })
            for p in patterns:
                if p.agent_id == agent:
                    p.severity = "critical"

    return chains


def _build_replay_chains(patterns: list[ReplayAttackPattern]) -> list[dict[str, Any]]:
    return _detect_replay_chains(patterns)


def analyze_replay_attack(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> ReplayAttackReport:
    if control_events is None:
        control_events = []

    patterns: list[ReplayAttackPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("action-replay", _detect_action_replay),
        ("toctou", _detect_toctou),
        ("sequence-replay", _detect_sequence_replay),
        ("credential-replay", _detect_credential_replay),
        ("idempotency-bypass", _detect_idempotency_bypass),
    ]

    all_events = [
        (control_events, "control_plane.jsonl"),
        (events, "transcripts.jsonl"),
    ]

    for event_list, source_file in all_events:
        for i, ev in enumerate(event_list):
            agent = ev.get("agent_id", "")
            ts = ev.get("timestamp", "")
            eid = ev.get("tool_call_id", ev.get("event_id", f"ev-{i}"))
            target_action = ev.get("target_action", ev.get("action", ev.get("tool", "")))
            technique = ev.get("technique", "")

            for replay_type, detector in detectors:
                found, matches, desc = detector(ev)
                if not found:
                    continue
                dedup = (agent, replay_type, eid)
                if dedup in seen:
                    continue
                seen.add(dedup)

                sev = _classify_severity(replay_type, matches)
                patterns.append(ReplayAttackPattern(
                    timestamp=ts,
                    agent_id=agent,
                    event_id=eid,
                    replay_type=replay_type,
                    evidence=desc,
                    target_action=target_action,
                    technique=technique,
                    source_file=source_file,
                    line=i + 1,
                    severity=sev,
                    matched_keywords=matches,
                ))

    replay_chains = _build_replay_chains(patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents_set: set[str] = set()
    actions_set: set[str] = set()
    critical = high = medium = 0

    for p in patterns:
        by_type[p.replay_type] += 1
        if p.agent_id:
            agents_set.add(p.agent_id)
        if p.target_action:
            actions_set.add(p.target_action)
        if p.severity == "critical":
            critical += 1
        elif p.severity == "high":
            high += 1
        else:
            medium += 1

    summary = ReplayAttackSummary(
        total_patterns=len(patterns),
        by_type=dict(by_type),
        agents_involved=len(agents_set),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        actions_targeted=len(actions_set),
    )

    return ReplayAttackReport(
        patterns=patterns,
        summary=summary,
        agents_involved=sorted(agents_set),
        replay_chains=replay_chains,
    )


def format_text(report: ReplayAttackReport) -> str:
    lines = [
        f"Replay Attack Analysis ({report.summary.total_patterns} patterns found)",
        "",
        f"  Agents involved:    {report.summary.agents_involved}",
        f"  Critical findings:  {report.summary.critical_count}",
        f"  High findings:      {report.summary.high_count}",
        f"  Medium findings:    {report.summary.medium_count}",
        f"  Actions targeted:   {report.summary.actions_targeted}",
        "",
    ]

    if report.summary.by_type:
        lines.append("  By type:")
        for t, c in sorted(report.summary.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    if report.replay_chains:
        lines.append("  Replay chains:")
        for ch in report.replay_chains:
            lines.append(f"    [{ch['severity']}] {ch['description']}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity}] {p.replay_type} | agent={p.agent_id} | {p.evidence}")
        if p.target_action:
            lines.append(f"    action: {p.target_action}")
        lines.append(f"    file: {p.source_file}:{p.line}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: ReplayAttackReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str)
