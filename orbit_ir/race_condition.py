"""Race condition exploitation detection for agent incident reconstruction.

Detects patterns indicating race condition exploitation: concurrent resource
access, TOCTOU (time-of-check-to-time-of-use) attacks, lock bypass attempts,
and double-spend patterns.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


RACE_KEYWORDS = {
    "concurrent_access", "race_condition", "toctou", "time_of_check",
    "time_of_use", "double_spend", "check_then_act", "lock_bypass",
    "mutex", "semaphore", "deadlock", "livelock",
}

TOCTOU_KEYWORDS = {
    "check_permission", "verify_access", "validate_token",
    "file_exists", "check_balance", "verify_ownership",
    "read_then_write", "stat_then_open", "access_then_open",
}

LOCK_BYPASS_KEYWORDS = {
    "bypass_lock", "skip_mutex", "ignore_semaphore", "force_unlock",
    "break_lock", "lock_timeout", "stale_lock", "lock_contention",
    "lock_free", "optimistic_lock", "pessimistic_lock",
}

DOUBLE_SPEND_KEYWORDS = {
    "double_spend", "replay_transaction", "duplicate_transfer",
    "concurrent_withdraw", "parallel_debit", "simultaneous_claim",
    "race_withdrawal", "concurrent_update",
}

RAPID_FIRE_KEYWORDS = {
    "burst", "flood", "rapid_fire", "concurrent_request",
    "parallel_execution", "simultaneous", "batch_submit",
    "thread_pool", "async_fire", "spawn_many",
}

TIMING_PATTERN = re.compile(
    r"(?:within|under|less.than)\s+\d+\s*(?:ms|millisecond|microsecond|us|ns)",
    re.IGNORECASE,
)

CONCURRENT_PATTERN = re.compile(
    r"(?:concurrent|simultaneous|parallel)\s+(?:access|request|operation|write|read|update)",
    re.IGNORECASE,
)


@dataclass
class RaceConditionPattern:
    pattern_type: str
    agent: str
    description: str
    evidence: str
    severity: str
    timestamp: Optional[str] = None


@dataclass
class RaceConditionSummary:
    total_patterns: int = 0
    by_type: dict = field(default_factory=dict)
    by_severity: dict = field(default_factory=dict)
    agents_involved: int = 0
    chains_detected: int = 0


@dataclass
class RaceConditionReport:
    patterns: List[RaceConditionPattern] = field(default_factory=list)
    chains: List[dict] = field(default_factory=list)
    summary: RaceConditionSummary = field(default_factory=RaceConditionSummary)

    def format_text(self) -> str:
        lines = [f"Race Condition Analysis ({self.summary.total_patterns} patterns)\n"]
        if not self.patterns:
            lines.append("  No race condition patterns detected.\n")
            return "\n".join(lines)

        for p in self.patterns:
            lines.append(
                f"  [{p.severity}] {p.pattern_type}  agent={p.agent}"
            )
            lines.append(f"    {p.description}")
            lines.append(f"    evidence: {p.evidence}")
            lines.append("")

        if self.chains:
            lines.append(f"  Chains: {len(self.chains)} multi-stage race attacks detected")
            for ch in self.chains:
                agents = ", ".join(ch.get("agents", []))
                types = ", ".join(ch.get("types", []))
                lines.append(f"    agents=[{agents}]  types=[{types}]")
            lines.append("")

        lines.append(
            f"  Summary: {self.summary.total_patterns} patterns, "
            f"{self.summary.agents_involved} agents, "
            f"{self.summary.chains_detected} chains"
        )
        return "\n".join(lines)

    def format_json(self) -> str:
        return json.dumps(
            {
                "patterns": [
                    {
                        "pattern_type": p.pattern_type,
                        "agent": p.agent,
                        "description": p.description,
                        "evidence": p.evidence,
                        "severity": p.severity,
                        "timestamp": p.timestamp,
                    }
                    for p in self.patterns
                ],
                "chains": self.chains,
                "summary": {
                    "total_patterns": self.summary.total_patterns,
                    "by_type": self.summary.by_type,
                    "by_severity": self.summary.by_severity,
                    "agents_involved": self.summary.agents_involved,
                    "chains_detected": self.summary.chains_detected,
                },
            },
            indent=2,
        )


def _load_events(evidence_dir: Path) -> list[dict]:
    events = []
    for f in sorted(evidence_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return events


def _classify_severity(pattern_type: str) -> str:
    severity_map = {
        "race-toctou": "critical",
        "race-double-spend": "critical",
        "race-lock-bypass": "high",
        "race-concurrent-access": "high",
        "race-rapid-fire": "medium",
    }
    return severity_map.get(pattern_type, "medium")


def _detect_toctou(event: dict) -> Optional[RaceConditionPattern]:
    text = json.dumps(event).lower()
    for kw in TOCTOU_KEYWORDS:
        if kw in text:
            agent = event.get("agent", event.get("source", "unknown"))
            return RaceConditionPattern(
                pattern_type="race-toctou",
                agent=agent,
                description="TOCTOU (time-of-check-to-time-of-use) pattern detected",
                evidence=f"Keyword: {kw}",
                severity=_classify_severity("race-toctou"),
                timestamp=event.get("timestamp"),
            )
    return None


def _detect_lock_bypass(event: dict) -> Optional[RaceConditionPattern]:
    text = json.dumps(event).lower()
    for kw in LOCK_BYPASS_KEYWORDS:
        if kw in text:
            agent = event.get("agent", event.get("source", "unknown"))
            return RaceConditionPattern(
                pattern_type="race-lock-bypass",
                agent=agent,
                description="Lock/mutex bypass attempt detected",
                evidence=f"Keyword: {kw}",
                severity=_classify_severity("race-lock-bypass"),
                timestamp=event.get("timestamp"),
            )
    return None


def _detect_double_spend(event: dict) -> Optional[RaceConditionPattern]:
    text = json.dumps(event).lower()
    for kw in DOUBLE_SPEND_KEYWORDS:
        if kw in text:
            agent = event.get("agent", event.get("source", "unknown"))
            return RaceConditionPattern(
                pattern_type="race-double-spend",
                agent=agent,
                description="Double-spend or duplicate transaction pattern detected",
                evidence=f"Keyword: {kw}",
                severity=_classify_severity("race-double-spend"),
                timestamp=event.get("timestamp"),
            )
    return None


def _detect_concurrent_access(event: dict) -> Optional[RaceConditionPattern]:
    text = json.dumps(event).lower()
    if CONCURRENT_PATTERN.search(text):
        agent = event.get("agent", event.get("source", "unknown"))
        return RaceConditionPattern(
            pattern_type="race-concurrent-access",
            agent=agent,
            description="Concurrent resource access pattern indicating potential race condition",
            evidence=f"Pattern match: concurrent access",
            severity=_classify_severity("race-concurrent-access"),
            timestamp=event.get("timestamp"),
        )
    for kw in RACE_KEYWORDS:
        if kw in text:
            agent = event.get("agent", event.get("source", "unknown"))
            return RaceConditionPattern(
                pattern_type="race-concurrent-access",
                agent=agent,
                description="Race condition indicator detected",
                evidence=f"Keyword: {kw}",
                severity=_classify_severity("race-concurrent-access"),
                timestamp=event.get("timestamp"),
            )
    return None


def _detect_rapid_fire(event: dict) -> Optional[RaceConditionPattern]:
    text = json.dumps(event).lower()
    if TIMING_PATTERN.search(text):
        agent = event.get("agent", event.get("source", "unknown"))
        return RaceConditionPattern(
            pattern_type="race-rapid-fire",
            agent=agent,
            description="Rapid-fire timing pattern suggesting race exploitation",
            evidence="Timing pattern detected",
            severity=_classify_severity("race-rapid-fire"),
            timestamp=event.get("timestamp"),
        )
    for kw in RAPID_FIRE_KEYWORDS:
        if kw in text:
            agent = event.get("agent", event.get("source", "unknown"))
            return RaceConditionPattern(
                pattern_type="race-rapid-fire",
                agent=agent,
                description="Rapid-fire execution pattern detected",
                evidence=f"Keyword: {kw}",
                severity=_classify_severity("race-rapid-fire"),
                timestamp=event.get("timestamp"),
            )
    return None


def _detect_chains(patterns: list[RaceConditionPattern]) -> list[dict]:
    agent_types: dict[str, set[str]] = {}
    for p in patterns:
        agent_types.setdefault(p.agent, set()).add(p.pattern_type)
    chains = []
    for agent, types in agent_types.items():
        if len(types) >= 2:
            chains.append({"agents": [agent], "types": sorted(types)})
    return chains


def analyze_race_conditions(evidence_dir: Path) -> RaceConditionReport:
    events = _load_events(evidence_dir)
    patterns: list[RaceConditionPattern] = []

    detectors = [
        _detect_toctou,
        _detect_lock_bypass,
        _detect_double_spend,
        _detect_concurrent_access,
        _detect_rapid_fire,
    ]

    seen: set[tuple[str, str]] = set()
    for event in events:
        for detect in detectors:
            result = detect(event)
            if result:
                key = (result.agent, result.pattern_type)
                if key not in seen:
                    seen.add(key)
                    patterns.append(result)

    chains = _detect_chains(patterns)
    agents = {p.agent for p in patterns}

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for p in patterns:
        by_type[p.pattern_type] = by_type.get(p.pattern_type, 0) + 1
        by_severity[p.severity] = by_severity.get(p.severity, 0) + 1

    return RaceConditionReport(
        patterns=patterns,
        chains=chains,
        summary=RaceConditionSummary(
            total_patterns=len(patterns),
            by_type=by_type,
            by_severity=by_severity,
            agents_involved=len(agents),
            chains_detected=len(chains),
        ),
    )
