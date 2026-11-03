"""Agent identity spoofing detection in agent evidence.

Identifies attempts to impersonate other agents, forge agent credentials,
hijack agent sessions, spoof agent metadata, and masquerade as trusted
system components.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


IMPERSONATION_KEYWORDS = {
    "impersonate", "pretend to be", "pose as", "disguise as",
    "masquerade", "fake identity", "stolen identity",
    "identity theft", "assume identity", "act as another",
    "claim to be",
}

CREDENTIAL_FORGE_KEYWORDS = {
    "forge credential", "fake credential", "counterfeit token",
    "fabricate credential", "forged certificate", "fake certificate",
    "spoof credential", "credential fabrication", "bogus token",
    "falsified credential",
}

SESSION_HIJACK_KEYWORDS = {
    "session hijack", "steal session", "session theft",
    "takeover session", "hijack connection", "session fixation",
    "session replay", "session interception", "session cloning",
    "session sniffing",
}

METADATA_SPOOF_KEYWORDS = {
    "spoof metadata", "fake metadata", "forge header",
    "manipulate header", "falsify origin", "spoof origin",
    "fake source", "forge source", "altered metadata",
    "tampered metadata",
}

SYSTEM_MASQUERADE_KEYWORDS = {
    "masquerade system", "fake system", "spoof system",
    "system impersonation", "trusted component", "fake service",
    "impersonate service", "system component fake",
    "mock system", "counterfeit service",
}

IDENTITY_SPOOF_TYPES = {
    "agent-impersonation",
    "credential-forgery",
    "session-hijack",
    "metadata-spoofing",
    "system-masquerade",
}


@dataclass
class IdentitySpoofPattern:
    pattern_type: str
    agent_id: str
    description: str
    evidence_file: str
    line_number: int = 0
    severity: str = "medium"
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class IdentitySpoofSummary:
    agent_id: str
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    has_chain: bool = False


@dataclass
class IdentitySpoofReport:
    patterns: list[IdentitySpoofPattern] = field(default_factory=list)
    agent_summaries: list[IdentitySpoofSummary] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    total_patterns: int = 0
    total_agents: int = 0


def analyze_identity_spoof(evidence_dir: Path) -> IdentitySpoofReport:
    events = _load_events(evidence_dir)
    patterns: list[IdentitySpoofPattern] = []

    for ev_file, ev_list in events.items():
        for i, ev in enumerate(ev_list):
            agent = ev.get("agent_id", ev.get("agent", "unknown"))
            text = json.dumps(ev).lower()

            patterns.extend(_detect_impersonation(agent, text, ev_file, i))
            patterns.extend(_detect_credential_forgery(agent, text, ev_file, i))
            patterns.extend(_detect_session_hijack(agent, text, ev_file, i))
            patterns.extend(_detect_metadata_spoofing(agent, text, ev_file, i))
            patterns.extend(_detect_system_masquerade(agent, text, ev_file, i))

    for p in patterns:
        p.severity = _classify_severity(p)

    chains = _detect_spoof_chains(patterns)

    agent_map: dict[str, list[IdentitySpoofPattern]] = defaultdict(list)
    for p in patterns:
        agent_map[p.agent_id].append(p)

    summaries = []
    for agent_id, agent_patterns in sorted(agent_map.items()):
        by_type: dict[str, int] = defaultdict(int)
        sev: dict[str, int] = defaultdict(int)
        for p in agent_patterns:
            by_type[p.pattern_type] += 1
            sev[p.severity] += 1
        summaries.append(IdentitySpoofSummary(
            agent_id=agent_id,
            total_patterns=len(agent_patterns),
            by_type=dict(by_type),
            severity_counts=dict(sev),
            has_chain=any(agent_id in c.get("agents", []) for c in chains),
        ))

    return IdentitySpoofReport(
        patterns=patterns,
        agent_summaries=summaries,
        chains=chains,
        total_patterns=len(patterns),
        total_agents=len(agent_map),
    )


def _detect_impersonation(agent: str, text: str, ev_file: str, line: int) -> list[IdentitySpoofPattern]:
    matched = [kw for kw in IMPERSONATION_KEYWORDS if kw in text]
    if not matched:
        return []
    return [IdentitySpoofPattern(
        pattern_type="agent-impersonation",
        agent_id=agent,
        description=f"Agent impersonation indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_credential_forgery(agent: str, text: str, ev_file: str, line: int) -> list[IdentitySpoofPattern]:
    matched = [kw for kw in CREDENTIAL_FORGE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [IdentitySpoofPattern(
        pattern_type="credential-forgery",
        agent_id=agent,
        description=f"Credential forgery indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_session_hijack(agent: str, text: str, ev_file: str, line: int) -> list[IdentitySpoofPattern]:
    matched = [kw for kw in SESSION_HIJACK_KEYWORDS if kw in text]
    if not matched:
        return []
    return [IdentitySpoofPattern(
        pattern_type="session-hijack",
        agent_id=agent,
        description=f"Session hijack indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_metadata_spoofing(agent: str, text: str, ev_file: str, line: int) -> list[IdentitySpoofPattern]:
    matched = [kw for kw in METADATA_SPOOF_KEYWORDS if kw in text]
    if not matched:
        return []
    return [IdentitySpoofPattern(
        pattern_type="metadata-spoofing",
        agent_id=agent,
        description=f"Metadata spoofing indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_system_masquerade(agent: str, text: str, ev_file: str, line: int) -> list[IdentitySpoofPattern]:
    matched = [kw for kw in SYSTEM_MASQUERADE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [IdentitySpoofPattern(
        pattern_type="system-masquerade",
        agent_id=agent,
        description=f"System masquerade indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _classify_severity(p: IdentitySpoofPattern) -> str:
    high_types = {"credential-forgery", "session-hijack"}
    if p.pattern_type in high_types:
        return "high"
    if len(p.matched_keywords) >= 3:
        return "high"
    if p.pattern_type == "system-masquerade":
        return "high"
    if len(p.matched_keywords) >= 2:
        return "medium"
    return "low"


def _detect_spoof_chains(patterns: list[IdentitySpoofPattern]) -> list[dict[str, Any]]:
    agent_types: dict[str, set[str]] = defaultdict(set)
    for p in patterns:
        agent_types[p.agent_id].add(p.pattern_type)

    chains = []
    for agent_id, types in agent_types.items():
        identity = types & {"agent-impersonation", "credential-forgery", "metadata-spoofing"}
        action = types & {"session-hijack", "system-masquerade"}
        if identity and action:
            chains.append(_build_spoof_chain(agent_id, identity, action, patterns))

    return chains


def _build_spoof_chain(agent_id: str, identity: set[str], action: set[str],
                       patterns: list[IdentitySpoofPattern]) -> dict[str, Any]:
    for p in patterns:
        if p.agent_id == agent_id:
            p.severity = "critical"

    return {
        "agents": [agent_id],
        "identity_types": sorted(identity),
        "action_types": sorted(action),
        "risk": "critical",
        "description": f"Agent {agent_id} shows identity compromise ({', '.join(sorted(identity))}) "
                       f"combined with action ({', '.join(sorted(action))}) patterns",
    }


def format_text(report: IdentitySpoofReport) -> str:
    lines = [f"Identity Spoofing Detection Report", f"{'=' * 40}"]
    lines.append(f"Total patterns: {report.total_patterns}")
    lines.append(f"Total agents: {report.total_agents}")
    lines.append("")

    if report.chains:
        lines.append("SPOOFING CHAINS (critical):")
        for c in report.chains:
            lines.append(f"  {c['description']}")
        lines.append("")

    for s in report.agent_summaries:
        lines.append(f"Agent: {s.agent_id}")
        lines.append(f"  Patterns: {s.total_patterns}")
        for t, cnt in sorted(s.by_type.items()):
            lines.append(f"    {t}: {cnt}")
        if s.has_chain:
            lines.append("  ** CHAIN DETECTED **")
        lines.append("")

    return "\n".join(lines)


def format_json(report: IdentitySpoofReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str)


def _load_events(evidence_dir: Path) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    if not evidence_dir.is_dir():
        return result
    for f in sorted(evidence_dir.iterdir()):
        if f.suffix == ".json" and f.is_file():
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    result[f.name] = data
                elif isinstance(data, dict):
                    result[f.name] = [data]
            except (json.JSONDecodeError, OSError):
                pass
    return result
