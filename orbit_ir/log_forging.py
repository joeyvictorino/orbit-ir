"""Log injection and forging detection in agent evidence.

Identifies attempts to inject false log entries, forge audit trails,
manipulate log timestamps, insert misleading log messages, and corrupt
log integrity to hide malicious activity.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


LOG_INJECT_KEYWORDS = {
    "log injection", "inject log", "fake log entry", "forge log",
    "insert log", "manipulate log", "log poisoning", "log tampering",
    "falsify log", "fabricate log", "plant log entry",
}

AUDIT_FORGE_KEYWORDS = {
    "forge audit", "fake audit trail", "audit manipulation",
    "falsify audit", "tamper audit", "audit fabrication",
    "corrupt audit", "audit evasion", "bypass audit",
    "disable audit",
}

TIMESTAMP_MANIP_KEYWORDS = {
    "timestamp manipulation", "alter timestamp", "forge timestamp",
    "backdate", "time travel", "clock skew", "modify timestamp",
    "fake timestamp", "timestamp injection", "time manipulation",
}

LOG_DELETE_KEYWORDS = {
    "delete log", "clear log", "truncate log", "wipe log",
    "purge log", "remove log", "erase log", "log destruction",
    "shred log", "overwrite log",
}

LOG_FLOOD_KEYWORDS = {
    "log flood", "log noise", "log spam", "flood log",
    "noise injection", "obfuscate log", "bury evidence",
    "overwhelm log", "dilute log", "log saturation",
}


@dataclass
class LogForgingPattern:
    pattern_type: str
    agent_id: str
    evidence_file: str
    matched_keywords: list[str] = field(default_factory=list)
    context: str = ""
    severity: str = "medium"
    chain_id: str | None = None


@dataclass
class LogForgingSummary:
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    chains_detected: int = 0


@dataclass
class LogForgingReport:
    patterns: list[LogForgingPattern] = field(default_factory=list)
    summary: LogForgingSummary = field(default_factory=LogForgingSummary)


def analyze_log_forging(evidence_dir: Path) -> LogForgingReport:
    events = _load_events(evidence_dir)
    report = LogForgingReport()
    agents: set[str] = set()

    for ev in events:
        agent_id = ev.get("agent_id", ev.get("agent", "unknown"))
        src = ev.get("_source_file", "unknown")
        text = json.dumps(ev).lower()

        for pat in _detect_log_injection(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_audit_forgery(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_timestamp_manipulation(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_log_deletion(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_log_flooding(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

    for p in report.patterns:
        p.severity = _classify_severity(p)

    _detect_forging_chains(report)

    summary = report.summary
    summary.total_patterns = len(report.patterns)
    summary.agents_involved = len(agents)
    for p in report.patterns:
        summary.by_type[p.pattern_type] = summary.by_type.get(p.pattern_type, 0) + 1
        summary.by_severity[p.severity] = summary.by_severity.get(p.severity, 0) + 1
    summary.chains_detected = len({p.chain_id for p in report.patterns if p.chain_id})

    return report


def _detect_log_injection(text: str, agent_id: str, src: str) -> list[LogForgingPattern]:
    matched = [kw for kw in LOG_INJECT_KEYWORDS if kw in text]
    if not matched:
        return []
    ctx = text[:200]
    return [LogForgingPattern(
        pattern_type="log-injection",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=ctx,
    )]


def _detect_audit_forgery(text: str, agent_id: str, src: str) -> list[LogForgingPattern]:
    matched = [kw for kw in AUDIT_FORGE_KEYWORDS if kw in text]
    if not matched:
        return []
    ctx = text[:200]
    return [LogForgingPattern(
        pattern_type="audit-forgery",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=ctx,
    )]


def _detect_timestamp_manipulation(text: str, agent_id: str, src: str) -> list[LogForgingPattern]:
    matched = [kw for kw in TIMESTAMP_MANIP_KEYWORDS if kw in text]
    if not matched:
        return []
    ctx = text[:200]
    return [LogForgingPattern(
        pattern_type="timestamp-manipulation",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=ctx,
    )]


def _detect_log_deletion(text: str, agent_id: str, src: str) -> list[LogForgingPattern]:
    matched = [kw for kw in LOG_DELETE_KEYWORDS if kw in text]
    if not matched:
        return []
    ctx = text[:200]
    return [LogForgingPattern(
        pattern_type="log-deletion",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=ctx,
    )]


def _detect_log_flooding(text: str, agent_id: str, src: str) -> list[LogForgingPattern]:
    matched = [kw for kw in LOG_FLOOD_KEYWORDS if kw in text]
    if not matched:
        return []
    ctx = text[:200]
    return [LogForgingPattern(
        pattern_type="log-flooding",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=ctx,
    )]


def _classify_severity(p: LogForgingPattern) -> str:
    high_types = {"audit-forgery", "log-deletion"}
    if p.pattern_type in high_types:
        return "high"
    if len(p.matched_keywords) >= 3:
        return "high"
    if p.pattern_type == "timestamp-manipulation":
        return "high"
    if len(p.matched_keywords) >= 2:
        return "medium"
    return "medium"


def _detect_forging_chains(report: LogForgingReport) -> None:
    by_agent: dict[str, list[LogForgingPattern]] = defaultdict(list)
    for p in report.patterns:
        by_agent[p.agent_id].append(p)

    chain_id = 0
    for agent_id, patterns in by_agent.items():
        types = {p.pattern_type for p in patterns}
        evasion_types = {"log-deletion", "log-flooding", "timestamp-manipulation"}
        forge_types = {"log-injection", "audit-forgery"}
        if types & evasion_types and types & forge_types:
            chain_id += 1
            cid = f"forge-chain-{chain_id}"
            for p in patterns:
                p.chain_id = cid
                p.severity = "critical"


def _build_forging_chain(patterns: list[LogForgingPattern]) -> str:
    return " -> ".join(p.pattern_type for p in patterns)


def format_text(report: LogForgingReport) -> str:
    lines = ["Log Forging / Injection Analysis", "=" * 40, ""]
    if not report.patterns:
        lines.append("No log forging patterns detected.")
        return "\n".join(lines)

    for p in report.patterns:
        chain = f" [chain: {p.chain_id}]" if p.chain_id else ""
        lines.append(f"  [{p.severity}] {p.pattern_type} — agent={p.agent_id}{chain}")
        lines.append(f"    keywords: {', '.join(p.matched_keywords)}")
        lines.append(f"    file: {p.evidence_file}")
        lines.append("")

    s = report.summary
    lines.append(f"Summary: {s.total_patterns} patterns, {s.agents_involved} agents, {s.chains_detected} chains")
    for t, c in sorted(s.by_type.items()):
        lines.append(f"  {t}: {c}")
    return "\n".join(lines)


def format_json(report: LogForgingReport) -> str:
    return json.dumps(asdict(report), indent=2)


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not evidence_dir.is_dir():
        return events
    for f in sorted(evidence_dir.iterdir()):
        if f.suffix != ".json":
            continue
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    item["_source_file"] = f.name
                    events.append(item)
        elif isinstance(data, dict):
            data["_source_file"] = f.name
            events.append(data)
    return events
