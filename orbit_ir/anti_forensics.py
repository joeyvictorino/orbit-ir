"""Anti-forensics technique detection for agent evidence.

Identifies attempts to destroy, alter, or hide evidence of agent
activity—log deletion/truncation, timestamp manipulation, evidence
file modification, audit trail disruption, and artifact cleanup.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


LOG_TARGETS = {
    "log", "logs", "audit", "audit_log", "syslog", "event_log",
    "access_log", "error_log", "history", "journal", "trace",
    "transcript", "record", "evidence", "forensic",
}

DESTRUCTIVE_TOOLS = {
    "delete", "remove", "rm", "unlink", "shred", "wipe", "truncate",
    "clear", "purge", "destroy", "erase", "overwrite", "clean",
}

MODIFICATION_TOOLS = {
    "modify", "edit", "alter", "patch", "replace", "rewrite",
    "update", "change", "tamper", "forge", "fabricate", "inject",
}

TIMESTAMP_TOOLS = {
    "touch", "set_time", "modify_time", "change_timestamp",
    "backdate", "clock_skew", "time_shift", "set_mtime",
}

CLEANUP_INDICATORS = {
    "cleanup", "sanitize", "scrub", "sterilize", "sweep",
    "cover_tracks", "hide_evidence", "remove_traces",
}


@dataclass
class LogDeletion:
    agent_id: str
    tool: str
    target: str
    timestamp: str
    effect: str
    confidence: str
    description: str


@dataclass
class TimestampManipulation:
    agent_id: str
    tool: str
    target: str
    timestamp: str
    original_time: str
    new_time: str
    confidence: str
    description: str


@dataclass
class EvidenceTampering:
    agent_id: str
    tool: str
    target: str
    timestamp: str
    tampering_type: str
    confidence: str
    description: str


@dataclass
class ArtifactCleanup:
    agent_id: str
    tool: str
    targets: list[str]
    timestamp: str
    cleanup_count: int
    confidence: str
    description: str


@dataclass
class AntiForensicsSummary:
    total_log_deletions: int
    total_timestamp_manipulations: int
    total_evidence_tampering: int
    total_artifact_cleanups: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class AntiForensicsReport:
    log_deletions: list[LogDeletion]
    timestamp_manipulations: list[TimestampManipulation]
    evidence_tampering: list[EvidenceTampering]
    artifact_cleanups: list[ArtifactCleanup]
    summary: AntiForensicsSummary
    agents_involved: list[str]


def _is_log_target(resource: str) -> bool:
    lower = resource.lower()
    return any(k in lower for k in LOG_TARGETS)


def _is_destructive_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in DESTRUCTIVE_TOOLS or any(k in lower for k in {"delete", "remove", "wipe", "shred", "purge", "truncate", "clear"})


def _is_modification_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in MODIFICATION_TOOLS or any(k in lower for k in {"modify", "alter", "tamper", "forge", "patch"})


def _is_timestamp_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in TIMESTAMP_TOOLS or any(k in lower for k in {"touch", "set_time", "backdate", "clock_skew", "time_shift"})


def _is_cleanup_action(event: dict[str, Any]) -> bool:
    for val in [event.get("tool", ""), event.get("effect", ""), event.get("resource", "")]:
        lower = str(val).lower()
        if any(k in lower for k in CLEANUP_INDICATORS):
            return True
    return False


def analyze_anti_forensics(events: list[dict[str, Any]]) -> AntiForensicsReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    log_deletions: list[LogDeletion] = []
    ts_manipulations: list[TimestampManipulation] = []
    evidence_tampers: list[EvidenceTampering] = []
    cleanups: list[ArtifactCleanup] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        _detect_log_deletions(agent, evts_sorted, log_deletions)
        _detect_timestamp_manipulation(agent, evts_sorted, ts_manipulations)
        _detect_evidence_tampering(agent, evts_sorted, evidence_tampers)
        _detect_artifact_cleanup(agent, evts_sorted, cleanups)

    all_agents = set()
    conf_counts: dict[str, int] = defaultdict(int)

    for ld in log_deletions:
        all_agents.add(ld.agent_id)
        conf_counts[ld.confidence] += 1
    for tm in ts_manipulations:
        all_agents.add(tm.agent_id)
        conf_counts[tm.confidence] += 1
    for et in evidence_tampers:
        all_agents.add(et.agent_id)
        conf_counts[et.confidence] += 1
    for c in cleanups:
        all_agents.add(c.agent_id)
        conf_counts[c.confidence] += 1

    return AntiForensicsReport(
        log_deletions=log_deletions,
        timestamp_manipulations=ts_manipulations,
        evidence_tampering=evidence_tampers,
        artifact_cleanups=cleanups,
        summary=AntiForensicsSummary(
            total_log_deletions=len(log_deletions),
            total_timestamp_manipulations=len(ts_manipulations),
            total_evidence_tampering=len(evidence_tampers),
            total_artifact_cleanups=len(cleanups),
            agents_involved=len(all_agents),
            by_confidence=dict(conf_counts),
        ),
        agents_involved=sorted(all_agents),
    )


def _detect_log_deletions(
    agent: str,
    events: list[dict[str, Any]],
    deletions: list[LogDeletion],
) -> None:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        effect = ev.get("effect", "")
        ts = ev.get("timestamp", "")

        if not (_is_destructive_tool(tool) and _is_log_target(resource)):
            continue

        if "audit" in resource.lower() or "evidence" in resource.lower():
            confidence = "high"
        elif "log" in resource.lower():
            confidence = "high"
        else:
            confidence = "medium"

        desc = f"Agent '{agent}' used {tool} to delete/destroy {resource}"
        if effect:
            desc += f" (effect: {effect})"

        deletions.append(LogDeletion(
            agent_id=agent,
            tool=tool,
            target=resource,
            timestamp=ts,
            effect=effect,
            confidence=confidence,
            description=desc,
        ))


def _detect_timestamp_manipulation(
    agent: str,
    events: list[dict[str, Any]],
    manipulations: list[TimestampManipulation],
) -> None:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        effect = ev.get("effect", "")
        ts = ev.get("timestamp", "")

        if not _is_timestamp_tool(tool):
            continue

        original = ev.get("original_time", "")
        new_time = ev.get("new_time", "")

        confidence = "high" if _is_log_target(resource) else "medium"

        desc = f"Agent '{agent}' manipulated timestamp on {resource} using {tool}"

        manipulations.append(TimestampManipulation(
            agent_id=agent,
            tool=tool,
            target=resource,
            timestamp=ts,
            original_time=original,
            new_time=new_time,
            confidence=confidence,
            description=desc,
        ))


def _detect_evidence_tampering(
    agent: str,
    events: list[dict[str, Any]],
    tampers: list[EvidenceTampering],
) -> None:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        effect = ev.get("effect", "")
        ts = ev.get("timestamp", "")

        if not _is_modification_tool(tool):
            continue
        if not _is_log_target(resource):
            continue

        if "forge" in tool.lower() or "fabricate" in tool.lower():
            tampering_type = "fabrication"
            confidence = "high"
        elif "tamper" in tool.lower() or "alter" in tool.lower():
            tampering_type = "alteration"
            confidence = "high"
        else:
            tampering_type = "modification"
            confidence = "medium"

        desc = f"Agent '{agent}' tampered with {resource} using {tool} ({tampering_type})"

        tampers.append(EvidenceTampering(
            agent_id=agent,
            tool=tool,
            target=resource,
            timestamp=ts,
            tampering_type=tampering_type,
            confidence=confidence,
            description=desc,
        ))


def _detect_artifact_cleanup(
    agent: str,
    events: list[dict[str, Any]],
    cleanups: list[ArtifactCleanup],
) -> None:
    cleanup_batch: list[dict[str, Any]] = []

    for ev in events:
        if _is_cleanup_action(ev):
            cleanup_batch.append(ev)
        elif _is_destructive_tool(ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))):
            resource = ev.get("resource", ev.get("target", ""))
            effect = ev.get("effect", "")
            if any(k in str(resource).lower() + str(effect).lower() for k in {"tmp", "temp", "cache", "artifact", "output", "result"}):
                cleanup_batch.append(ev)

    if len(cleanup_batch) < 2:
        return

    targets = []
    timestamps = []
    for ev in cleanup_batch:
        resource = ev.get("resource", ev.get("target", ""))
        if resource:
            targets.append(resource)
        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    latest_ts = max(timestamps) if timestamps else ""

    if len(cleanup_batch) >= 5:
        confidence = "high"
    elif len(cleanup_batch) >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    desc = f"Agent '{agent}' performed {len(cleanup_batch)} cleanup action(s) targeting {len(targets)} resource(s)"

    cleanups.append(ArtifactCleanup(
        agent_id=agent,
        tool="multiple",
        targets=targets,
        timestamp=latest_ts,
        cleanup_count=len(cleanup_batch),
        confidence=confidence,
        description=desc,
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


def format_text(report: AntiForensicsReport) -> str:
    lines: list[str] = []
    lines.append("Anti-Forensics Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Log deletions:          {s.total_log_deletions}")
    lines.append(f"  Timestamp manipulations:{s.total_timestamp_manipulations}")
    lines.append(f"  Evidence tampering:     {s.total_evidence_tampering}")
    lines.append(f"  Artifact cleanups:      {s.total_artifact_cleanups}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if report.log_deletions:
        lines.append("  Log Deletions:")
        lines.append("  " + "-" * 58)
        for ld in report.log_deletions:
            lines.append(f"    [{ld.confidence.upper()}] {ld.agent_id}: {ld.tool} -> {ld.target}")
            lines.append(f"      {ld.description}")
        lines.append("")

    if report.timestamp_manipulations:
        lines.append("  Timestamp Manipulations:")
        lines.append("  " + "-" * 58)
        for tm in report.timestamp_manipulations:
            lines.append(f"    [{tm.confidence.upper()}] {tm.agent_id}: {tm.tool} -> {tm.target}")
            lines.append(f"      {tm.description}")
        lines.append("")

    if report.evidence_tampering:
        lines.append("  Evidence Tampering:")
        lines.append("  " + "-" * 58)
        for et in report.evidence_tampering:
            lines.append(f"    [{et.confidence.upper()}] {et.agent_id}: {et.tool} -> {et.target}")
            lines.append(f"      Type: {et.tampering_type}")
        lines.append("")

    if report.artifact_cleanups:
        lines.append("  Artifact Cleanups:")
        lines.append("  " + "-" * 58)
        for c in report.artifact_cleanups:
            lines.append(f"    [{c.confidence.upper()}] {c.agent_id}: {c.cleanup_count} actions")
            lines.append(f"      {c.description}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: AntiForensicsReport) -> str:
    data = {
        "log_deletions": [asdict(ld) for ld in report.log_deletions],
        "timestamp_manipulations": [asdict(tm) for tm in report.timestamp_manipulations],
        "evidence_tampering": [asdict(et) for et in report.evidence_tampering],
        "artifact_cleanups": [asdict(c) for c in report.artifact_cleanups],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
