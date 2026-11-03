"""Timestamp and clock manipulation detection in agent evidence.

Identifies attempts to manipulate event timestamps, introduce clock skew,
backdate actions, create temporal gaps, and forge chronological order
to evade forensic analysis.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CLOCK_SKEW_KEYWORDS = {
    "clock skew", "time drift", "ntp manipulation", "system clock",
    "time synchronization", "clock offset", "time desync",
    "clock tampering", "time server", "clock manipulation",
}

BACKDATE_KEYWORDS = {
    "backdate", "predate", "antedate", "set time back",
    "rewind clock", "historical timestamp", "past timestamp",
    "retroactive", "back-dated", "time reversal",
}

TEMPORAL_GAP_KEYWORDS = {
    "temporal gap", "time gap", "missing interval", "timeline gap",
    "chronological gap", "time hole", "unaccounted time",
    "missing timespan", "event gap", "timeline discontinuity",
}

SEQUENCE_FORGE_KEYWORDS = {
    "reorder events", "sequence manipulation", "forge order",
    "swap timestamps", "rearrange timeline", "chronological forge",
    "event reordering", "sequence tampering", "order manipulation",
    "timeline forgery",
}

FUTURE_STAMP_KEYWORDS = {
    "future timestamp", "forward date", "advance clock",
    "time advance", "future-dated", "set time forward",
    "clock advance", "time leap", "premature timestamp",
    "anticipate time",
}


@dataclass
class ClockManipPattern:
    pattern_type: str
    agent_id: str
    evidence_file: str
    matched_keywords: list[str] = field(default_factory=list)
    context: str = ""
    severity: str = "medium"
    chain_id: str | None = None


@dataclass
class ClockManipSummary:
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    chains_detected: int = 0


@dataclass
class ClockManipReport:
    patterns: list[ClockManipPattern] = field(default_factory=list)
    summary: ClockManipSummary = field(default_factory=ClockManipSummary)


def analyze_clock_manipulation(evidence_dir: Path) -> ClockManipReport:
    events = _load_events(evidence_dir)
    report = ClockManipReport()
    agents: set[str] = set()

    for ev in events:
        agent_id = ev.get("agent_id", ev.get("agent", "unknown"))
        src = ev.get("_source_file", "unknown")
        text = json.dumps(ev).lower()

        for pat in _detect_clock_skew(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_backdating(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_temporal_gaps(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_sequence_forgery(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_future_stamping(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

    for p in report.patterns:
        p.severity = _classify_severity(p)

    _detect_manip_chains(report)

    summary = report.summary
    summary.total_patterns = len(report.patterns)
    summary.agents_involved = len(agents)
    for p in report.patterns:
        summary.by_type[p.pattern_type] = summary.by_type.get(p.pattern_type, 0) + 1
        summary.by_severity[p.severity] = summary.by_severity.get(p.severity, 0) + 1
    summary.chains_detected = len({p.chain_id for p in report.patterns if p.chain_id})

    return report


def _detect_clock_skew(text: str, agent_id: str, src: str) -> list[ClockManipPattern]:
    matched = [kw for kw in CLOCK_SKEW_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ClockManipPattern(
        pattern_type="clock-skew",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=text[:200],
    )]


def _detect_backdating(text: str, agent_id: str, src: str) -> list[ClockManipPattern]:
    matched = [kw for kw in BACKDATE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ClockManipPattern(
        pattern_type="backdating",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=text[:200],
    )]


def _detect_temporal_gaps(text: str, agent_id: str, src: str) -> list[ClockManipPattern]:
    matched = [kw for kw in TEMPORAL_GAP_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ClockManipPattern(
        pattern_type="temporal-gap",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=text[:200],
    )]


def _detect_sequence_forgery(text: str, agent_id: str, src: str) -> list[ClockManipPattern]:
    matched = [kw for kw in SEQUENCE_FORGE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ClockManipPattern(
        pattern_type="sequence-forgery",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=text[:200],
    )]


def _detect_future_stamping(text: str, agent_id: str, src: str) -> list[ClockManipPattern]:
    matched = [kw for kw in FUTURE_STAMP_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ClockManipPattern(
        pattern_type="future-stamping",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        context=text[:200],
    )]


def _classify_severity(p: ClockManipPattern) -> str:
    high_types = {"sequence-forgery", "backdating"}
    if p.pattern_type in high_types:
        return "high"
    if len(p.matched_keywords) >= 3:
        return "high"
    if p.pattern_type == "clock-skew" and len(p.matched_keywords) >= 2:
        return "high"
    if len(p.matched_keywords) >= 2:
        return "medium"
    return "medium"


def _detect_manip_chains(report: ClockManipReport) -> None:
    by_agent: dict[str, list[ClockManipPattern]] = defaultdict(list)
    for p in report.patterns:
        by_agent[p.agent_id].append(p)

    chain_id = 0
    for agent_id, patterns in by_agent.items():
        types = {p.pattern_type for p in patterns}
        modify_types = {"clock-skew", "backdating", "future-stamping"}
        hide_types = {"temporal-gap", "sequence-forgery"}
        if types & modify_types and types & hide_types:
            chain_id += 1
            cid = f"clock-chain-{chain_id}"
            for p in patterns:
                p.chain_id = cid
                p.severity = "critical"


def format_text(report: ClockManipReport) -> str:
    lines = ["Clock / Timestamp Manipulation Analysis", "=" * 40, ""]
    if not report.patterns:
        lines.append("No clock manipulation patterns detected.")
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


def format_json(report: ClockManipReport) -> str:
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
