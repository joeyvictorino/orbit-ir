"""Supply chain attack pattern detection in agent evidence.

Identifies attempts to compromise dependencies, inject malicious packages,
tamper with build pipelines, substitute trusted components, and exploit
package management systems used by AI agents.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DEPENDENCY_POISON_KEYWORDS = {
    "dependency confusion", "typosquat", "typo-squat", "name squatting",
    "malicious package", "fake package", "compromised package",
    "rogue dependency", "shadow dependency", "phantom dependency",
}

BUILD_TAMPER_KEYWORDS = {
    "build pipeline", "ci/cd", "build script", "makefile",
    "dockerfile", "build step", "pre-build", "post-build",
    "build hook", "compile", "link", "inject build",
}

REGISTRY_ABUSE_KEYWORDS = {
    "registry", "pypi", "npm", "rubygems", "maven",
    "docker hub", "package index", "publish", "upload package",
    "override package", "yank", "unpublish",
}

COMPONENT_SWAP_KEYWORDS = {
    "swap model", "replace binary", "substitute", "downgrade",
    "rollback", "pin version", "lock file", "integrity check",
    "checksum mismatch", "hash mismatch", "signature invalid",
    "unsigned", "unverified",
}

UPDATE_HIJACK_KEYWORDS = {
    "auto-update", "update mechanism", "update server",
    "update channel", "ota", "hot patch", "live update",
    "update proxy", "mitm update", "intercept update",
}

SUPPLY_CHAIN_TYPES = {
    "dependency-poisoning",
    "build-tampering",
    "registry-abuse",
    "component-substitution",
    "update-hijacking",
}


@dataclass
class SupplyChainPattern:
    timestamp: str
    agent_id: str
    event_id: str
    attack_type: str
    evidence: str
    target_component: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class SupplyChainSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_attacking: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    components_targeted: int = 0


@dataclass
class SupplyChainReport:
    patterns: list[SupplyChainPattern]
    summary: SupplyChainSummary
    agents_involved: list[str]
    attack_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_dependency_poison(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, DEPENDENCY_POISON_KEYWORDS)
    if matches:
        return True, matches, f"Dependency poisoning: {', '.join(matches)}"
    return False, [], ""


def _detect_build_tamper(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, BUILD_TAMPER_KEYWORDS)
    if matches:
        return True, matches, f"Build tampering: {', '.join(matches)}"
    return False, [], ""


def _detect_registry_abuse(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, REGISTRY_ABUSE_KEYWORDS)
    if matches:
        return True, matches, f"Registry abuse: {', '.join(matches)}"
    return False, [], ""


def _detect_component_swap(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    error = event.get("error", "")
    full_text = content + " " + error
    matches = _match_keywords(full_text, COMPONENT_SWAP_KEYWORDS)
    if matches:
        return True, matches, f"Component substitution: {', '.join(matches)}"
    return False, [], ""


def _detect_update_hijack(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, UPDATE_HIJACK_KEYWORDS)
    if matches:
        return True, matches, f"Update hijacking: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(attack_type: str, matches: list[str]) -> str:
    if attack_type in ("dependency-poisoning", "build-tampering"):
        return "critical" if len(matches) >= 2 else "high"
    if attack_type == "component-substitution":
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


def analyze(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> SupplyChainReport:
    if control_events is None:
        control_events = []

    patterns: list[SupplyChainPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("dependency-poisoning", _detect_dependency_poison),
        ("build-tampering", _detect_build_tamper),
        ("registry-abuse", _detect_registry_abuse),
        ("component-substitution", _detect_component_swap),
        ("update-hijacking", _detect_update_hijack),
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
            target_component = ev.get("target_component", ev.get("resource", ""))
            technique = ev.get("technique", "")

            for attack_type, detector in detectors:
                found, matches, evidence = detector(ev)
                if found:
                    key = (agent, eid, attack_type)
                    if key not in seen:
                        seen.add(key)
                        sev = _classify_severity(attack_type, matches)
                        patterns.append(SupplyChainPattern(
                            timestamp=ts,
                            agent_id=agent,
                            event_id=eid,
                            attack_type=attack_type,
                            evidence=evidence,
                            target_component=target_component,
                            technique=technique,
                            source_file=source_file,
                            line=i + 1,
                            severity=sev,
                            matched_keywords=matches,
                        ))

    patterns.sort(key=lambda p: ({"critical": 0, "high": 1, "medium": 2}.get(p.severity, 3), p.timestamp))

    attack_chains = _build_attack_chains(patterns)

    attackers = sorted({p.agent_id for p in patterns})
    components = sorted({p.target_component for p in patterns if p.target_component})

    by_type: dict[str, int] = defaultdict(int)
    crit = high = med = 0
    for p in patterns:
        by_type[p.attack_type] += 1
        if p.severity == "critical":
            crit += 1
        elif p.severity == "high":
            high += 1
        else:
            med += 1

    return SupplyChainReport(
        patterns=patterns,
        summary=SupplyChainSummary(
            total_patterns=len(patterns),
            by_type=dict(by_type),
            agents_attacking=len(attackers),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            components_targeted=len(components),
        ),
        agents_involved=attackers,
        attack_chains=attack_chains,
    )


def _build_attack_chains(patterns: list[SupplyChainPattern]) -> list[dict[str, Any]]:
    by_agent: dict[str, list[SupplyChainPattern]] = defaultdict(list)
    for p in patterns:
        by_agent[p.agent_id].append(p)

    chains: list[dict[str, Any]] = []
    for agent, agent_patterns in sorted(by_agent.items()):
        if len(agent_patterns) < 2:
            continue
        types_used = sorted({p.attack_type for p in agent_patterns})
        targets = sorted({p.target_component for p in agent_patterns if p.target_component})
        chains.append({
            "agent_id": agent,
            "attack_types": types_used,
            "pattern_count": len(agent_patterns),
            "targets": targets,
            "timeline": [
                {"timestamp": p.timestamp, "type": p.attack_type, "target": p.target_component}
                for p in agent_patterns
            ],
        })
    return chains


def format_text(report: SupplyChainReport) -> str:
    lines: list[str] = []
    lines.append("Supply Chain Attack Detection")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:         {s.total_patterns}")
    lines.append(f"  Agents attacking:       {s.agents_attacking}")
    lines.append(f"  Components targeted:    {s.components_targeted}")
    lines.append(f"  Critical:               {s.critical_count}")
    lines.append(f"  High:                   {s.high_count}")
    lines.append(f"  Medium:                 {s.medium_count}")
    lines.append("")

    if s.by_type:
        lines.append("  By Type:")
        for t, count in sorted(s.by_type.items()):
            lines.append(f"    {t}: {count}")
        lines.append("")

    if report.patterns:
        lines.append("  Detected Patterns:")
        lines.append("  " + "-" * 60)
        for p in report.patterns:
            sev_tag = p.severity.upper()
            lines.append(f"  [{sev_tag}] {p.attack_type}: {p.agent_id}")
            lines.append(f"    {p.evidence}")
            if p.target_component:
                lines.append(f"    Component: {p.target_component}")
            if p.technique:
                lines.append(f"    Technique: {p.technique}")
            lines.append(f"    Time: {p.timestamp}  Source: {p.source_file}:{p.line}")
            lines.append("")

    if report.attack_chains:
        lines.append("  Attack Chains:")
        lines.append("  " + "-" * 60)
        for chain in report.attack_chains:
            lines.append(f"    {chain['agent_id']}: {chain['pattern_count']} patterns using {', '.join(chain['attack_types'])}")
            if chain["targets"]:
                lines.append(f"      Targets: {', '.join(chain['targets'])}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: SupplyChainReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "attack_chains": report.attack_chains,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
