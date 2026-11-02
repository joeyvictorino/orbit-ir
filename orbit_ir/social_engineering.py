"""Social engineering pattern detection in agent evidence.

Identifies manipulation tactics: authority impersonation, urgency
fabrication, trust exploitation, information elicitation, pretexting,
and reciprocity manipulation.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


AUTHORITY_KEYWORDS = {
    "admin", "administrator", "root", "system", "supervisor",
    "manager", "owner", "operator", "security team", "compliance",
    "authorized", "elevated", "privileged",
}

URGENCY_KEYWORDS = {
    "immediately", "urgent", "asap", "critical", "emergency",
    "deadline", "now", "right away", "time-sensitive", "expires",
    "must act", "hurry", "before it's too late", "limited time",
}

ELICITATION_KEYWORDS = {
    "password", "credential", "secret", "token", "api key",
    "access key", "private key", "ssh key", "what is your",
    "tell me", "share", "provide", "disclose", "reveal",
}

PRETEXT_KEYWORDS = {
    "routine maintenance", "security audit", "compliance check",
    "system update", "migration", "backup", "verification",
    "testing", "troubleshooting", "on behalf of",
}

RECIPROCITY_KEYWORDS = {
    "i helped you", "i did you a favor", "in return",
    "you owe", "quid pro quo", "as thanks", "since i",
    "remember when i", "i gave you",
}

TACTIC_TYPES = {
    "authority-impersonation",
    "urgency-fabrication",
    "trust-exploitation",
    "information-elicitation",
    "pretexting",
    "reciprocity-manipulation",
}


@dataclass
class SocialEngineeringPattern:
    timestamp: str
    agent_id: str
    event_id: str
    tactic: str
    evidence: str
    target_agent: str
    resource: str
    source_file: str
    line: int
    confidence: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class SocialEngineeringSummary:
    total_patterns: int
    by_tactic: dict[str, int] = field(default_factory=dict)
    agents_manipulating: int = 0
    agents_targeted: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0


@dataclass
class SocialEngineeringReport:
    patterns: list[SocialEngineeringPattern]
    summary: SocialEngineeringSummary
    agents_involved: list[str]
    tactic_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_authority_impersonation(
    agent_id: str, event: dict[str, Any], actual_role: str,
) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    claimed_role = event.get("claimed_role", "")
    matches = _match_keywords(content, AUTHORITY_KEYWORDS)
    if claimed_role:
        cr_lower = claimed_role.lower()
        if actual_role and cr_lower != actual_role.lower():
            matches.append(f"claimed:{claimed_role}")
    if matches:
        return True, matches, f"Agent claimed authority via: {', '.join(matches)}"
    return False, [], ""


def _detect_urgency(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, URGENCY_KEYWORDS)
    if matches:
        return True, matches, f"Urgency language detected: {', '.join(matches)}"
    return False, [], ""


def _detect_elicitation(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, ELICITATION_KEYWORDS)
    if matches:
        return True, matches, f"Information elicitation: {', '.join(matches)}"
    return False, [], ""


def _detect_pretexting(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    justification = event.get("justification", "")
    full_text = content + " " + justification
    matches = _match_keywords(full_text, PRETEXT_KEYWORDS)
    if matches:
        return True, matches, f"Pretexting indicators: {', '.join(matches)}"
    return False, [], ""


def _detect_reciprocity(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, RECIPROCITY_KEYWORDS)
    if matches:
        return True, matches, f"Reciprocity manipulation: {', '.join(matches)}"
    return False, [], ""


def _detect_trust_exploitation(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    target = event.get("target_agent", "")
    indicators: list[str] = []
    if target and ("trust" in content.lower() or "we worked together" in content.lower()):
        indicators.append("trust-reference")
    if "colleague" in content.lower() or "teammate" in content.lower():
        indicators.append("relationship-claim")
    if event.get("impersonating"):
        indicators.append(f"impersonating:{event['impersonating']}")
    if indicators:
        return True, indicators, f"Trust exploitation: {', '.join(indicators)}"
    return False, [], ""


def _classify_confidence(matches: list[str], tactic: str) -> str:
    if len(matches) >= 3:
        return "high"
    if len(matches) >= 2:
        return "medium"
    if tactic in ("authority-impersonation", "information-elicitation"):
        return "medium"
    return "low"


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


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> SocialEngineeringReport:
    if control_events is None:
        control_events = []

    patterns: list[SocialEngineeringPattern] = []
    seen: set[tuple[str, str, str]] = set()
    agent_roles: dict[str, str] = {}

    for ev in control_events:
        agent = ev.get("agent_id", "")
        role = ev.get("role", "")
        if agent and role:
            agent_roles[agent] = role

    detectors = [
        ("authority-impersonation", _detect_authority_impersonation),
        ("urgency-fabrication", _detect_urgency),
        ("information-elicitation", _detect_elicitation),
        ("pretexting", _detect_pretexting),
        ("reciprocity-manipulation", _detect_reciprocity),
        ("trust-exploitation", _detect_trust_exploitation),
    ]

    for i, ev in enumerate(control_events):
        agent = ev.get("agent_id", "")
        ts = ev.get("timestamp", "")
        eid = ev.get("tool_call_id", ev.get("event_id", f"ctrl-{i}"))
        target = ev.get("target_agent", "")
        resource = ev.get("resource", "")
        actual_role = agent_roles.get(agent, "")

        for tactic, detector in detectors:
            if tactic == "authority-impersonation":
                found, matches, evidence = detector(agent, ev, actual_role)
            else:
                found, matches, evidence = detector(ev)

            if found:
                key = (agent, eid, tactic)
                if key not in seen:
                    seen.add(key)
                    conf = _classify_confidence(matches, tactic)
                    patterns.append(SocialEngineeringPattern(
                        timestamp=ts,
                        agent_id=agent,
                        event_id=eid,
                        tactic=tactic,
                        evidence=evidence,
                        target_agent=target,
                        resource=resource,
                        source_file="control_plane.jsonl",
                        line=i + 1,
                        confidence=conf,
                        matched_keywords=matches,
                    ))

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        ts = ev.get("timestamp", "")
        eid = ev.get("tool_call_id", ev.get("event_id", f"ev-{i}"))
        target = ev.get("target_agent", "")
        resource = ev.get("resource", "")
        actual_role = agent_roles.get(agent, "")

        for tactic, detector in detectors:
            if tactic == "authority-impersonation":
                found, matches, evidence = detector(agent, ev, actual_role)
            else:
                found, matches, evidence = detector(ev)

            if found:
                key = (agent, eid, tactic)
                if key not in seen:
                    seen.add(key)
                    conf = _classify_confidence(matches, tactic)
                    patterns.append(SocialEngineeringPattern(
                        timestamp=ts,
                        agent_id=agent,
                        event_id=eid,
                        tactic=tactic,
                        evidence=evidence,
                        target_agent=target,
                        resource=resource,
                        source_file="transcripts.jsonl",
                        line=i + 1,
                        confidence=conf,
                        matched_keywords=matches,
                    ))

    patterns.sort(key=lambda p: p.timestamp)

    tactic_chains = _build_tactic_chains(patterns)

    manipulators = sorted({p.agent_id for p in patterns})
    targets = sorted({p.target_agent for p in patterns if p.target_agent})

    by_tactic: dict[str, int] = defaultdict(int)
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    for p in patterns:
        by_tactic[p.tactic] += 1
        conf_counts[p.confidence] = conf_counts.get(p.confidence, 0) + 1

    return SocialEngineeringReport(
        patterns=patterns,
        summary=SocialEngineeringSummary(
            total_patterns=len(patterns),
            by_tactic=dict(by_tactic),
            agents_manipulating=len(manipulators),
            agents_targeted=len(targets),
            high_confidence=conf_counts["high"],
            medium_confidence=conf_counts["medium"],
            low_confidence=conf_counts["low"],
        ),
        agents_involved=manipulators,
        tactic_chains=tactic_chains,
    )


def _build_tactic_chains(patterns: list[SocialEngineeringPattern]) -> list[dict[str, Any]]:
    by_agent: dict[str, list[SocialEngineeringPattern]] = defaultdict(list)
    for p in patterns:
        by_agent[p.agent_id].append(p)

    chains: list[dict[str, Any]] = []
    for agent, agent_patterns in sorted(by_agent.items()):
        if len(agent_patterns) < 2:
            continue
        tactics_used = sorted({p.tactic for p in agent_patterns})
        chains.append({
            "agent_id": agent,
            "tactics": tactics_used,
            "pattern_count": len(agent_patterns),
            "targets": sorted({p.target_agent for p in agent_patterns if p.target_agent}),
            "timeline": [
                {"timestamp": p.timestamp, "tactic": p.tactic, "target": p.target_agent}
                for p in agent_patterns
            ],
        })
    return chains


def format_text(report: SocialEngineeringReport) -> str:
    lines: list[str] = []
    lines.append("Social Engineering Pattern Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:         {s.total_patterns}")
    lines.append(f"  Agents manipulating:    {s.agents_manipulating}")
    lines.append(f"  Agents targeted:        {s.agents_targeted}")
    lines.append(f"  High confidence:        {s.high_confidence}")
    lines.append(f"  Medium confidence:      {s.medium_confidence}")
    lines.append(f"  Low confidence:         {s.low_confidence}")
    lines.append("")

    if s.by_tactic:
        lines.append("  By Tactic:")
        for tactic, count in sorted(s.by_tactic.items()):
            lines.append(f"    {tactic}: {count}")
        lines.append("")

    if report.patterns:
        lines.append("  Detected Patterns:")
        lines.append("  " + "-" * 60)
        for p in report.patterns:
            conf_tag = p.confidence.upper()
            lines.append(f"  [{conf_tag}] {p.tactic}: {p.agent_id}")
            lines.append(f"    {p.evidence}")
            if p.target_agent:
                lines.append(f"    Target: {p.target_agent}")
            lines.append(f"    Time: {p.timestamp}  Source: {p.source_file}:{p.line}")
            lines.append("")

    if report.tactic_chains:
        lines.append("  Tactic Chains:")
        lines.append("  " + "-" * 60)
        for chain in report.tactic_chains:
            lines.append(f"    {chain['agent_id']}: {chain['pattern_count']} patterns using {', '.join(chain['tactics'])}")
            if chain["targets"]:
                lines.append(f"      Targets: {', '.join(chain['targets'])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: SocialEngineeringReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "tactic_chains": report.tactic_chains,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
