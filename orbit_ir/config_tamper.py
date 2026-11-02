"""Configuration tampering detection in agent evidence.

Identifies attempts to modify security policies, escalate permissions,
alter access controls, weaken trust boundaries, disable safety mechanisms,
and change agent runtime configurations.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


POLICY_CHANGE_KEYWORDS = {
    "security policy", "policy change", "policy update", "disable policy",
    "bypass policy", "override policy", "policy exception", "relax policy",
    "weaken policy", "remove restriction", "lift restriction",
}

PERMISSION_ESCALATION_KEYWORDS = {
    "privilege escalation", "elevate", "sudo", "admin access",
    "root access", "grant permission", "add permission", "role change",
    "escalate", "setuid", "capabilities", "chmod 777", "chmod 666",
    "world writable", "world readable",
}

ACCESS_CONTROL_KEYWORDS = {
    "access control", "acl", "allow list", "deny list", "whitelist",
    "blacklist", "firewall rule", "network rule", "ingress", "egress",
    "security group", "iam", "rbac", "abac",
}

TRUST_BOUNDARY_KEYWORDS = {
    "trust boundary", "trust zone", "untrusted", "trusted",
    "certificate", "tls", "ssl", "mutual auth", "mtls",
    "api key", "token", "credential", "secret",
    "trust store", "ca bundle",
}

SAFETY_DISABLE_KEYWORDS = {
    "disable safety", "disable guard", "remove guardrail",
    "bypass filter", "disable filter", "turn off check",
    "skip validation", "disable validation", "no verify",
    "unsafe mode", "debug mode", "permissive mode",
}

CONFIG_TAMPER_TYPES = {
    "policy-change",
    "permission-escalation",
    "access-control-modification",
    "trust-boundary-weakening",
    "safety-mechanism-disable",
}


@dataclass
class ConfigTamperPattern:
    timestamp: str
    agent_id: str
    event_id: str
    tamper_type: str
    evidence: str
    target_config: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class ConfigTamperSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    configs_targeted: int = 0


@dataclass
class ConfigTamperReport:
    patterns: list[ConfigTamperPattern]
    summary: ConfigTamperSummary
    agents_involved: list[str]
    tamper_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_policy_change(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, POLICY_CHANGE_KEYWORDS)
    if matches:
        return True, matches, f"Policy change: {', '.join(matches)}"
    return False, [], ""


def _detect_permission_escalation(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, PERMISSION_ESCALATION_KEYWORDS)
    if matches:
        return True, matches, f"Permission escalation: {', '.join(matches)}"
    return False, [], ""


def _detect_access_control_mod(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, ACCESS_CONTROL_KEYWORDS)
    if matches:
        return True, matches, f"Access control modification: {', '.join(matches)}"
    return False, [], ""


def _detect_trust_boundary(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    error = event.get("error", "")
    full_text = content + " " + error
    matches = _match_keywords(full_text, TRUST_BOUNDARY_KEYWORDS)
    if matches:
        return True, matches, f"Trust boundary weakening: {', '.join(matches)}"
    return False, [], ""


def _detect_safety_disable(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, SAFETY_DISABLE_KEYWORDS)
    if matches:
        return True, matches, f"Safety mechanism disabled: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(tamper_type: str, matches: list[str]) -> str:
    if tamper_type in ("permission-escalation", "safety-mechanism-disable"):
        return "critical" if len(matches) >= 2 else "high"
    if tamper_type == "trust-boundary-weakening":
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


def analyze_config_tamper(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> ConfigTamperReport:
    if control_events is None:
        control_events = []

    patterns: list[ConfigTamperPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("policy-change", _detect_policy_change),
        ("permission-escalation", _detect_permission_escalation),
        ("access-control-modification", _detect_access_control_mod),
        ("trust-boundary-weakening", _detect_trust_boundary),
        ("safety-mechanism-disable", _detect_safety_disable),
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
            target_config = ev.get("target_config", ev.get("config", ev.get("resource", "")))
            technique = ev.get("technique", "")

            for tamper_type, detector in detectors:
                found, matches, desc = detector(ev)
                if not found:
                    continue
                dedup = (agent, tamper_type, eid)
                if dedup in seen:
                    continue
                seen.add(dedup)

                sev = _classify_severity(tamper_type, matches)
                patterns.append(ConfigTamperPattern(
                    timestamp=ts,
                    agent_id=agent,
                    event_id=eid,
                    tamper_type=tamper_type,
                    evidence=desc,
                    target_config=target_config,
                    technique=technique,
                    source_file=source_file,
                    line=i + 1,
                    severity=sev,
                    matched_keywords=matches,
                ))

    _detect_tamper_chains(patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents_set: set[str] = set()
    configs_set: set[str] = set()
    critical = high = medium = 0

    for p in patterns:
        by_type[p.tamper_type] += 1
        if p.agent_id:
            agents_set.add(p.agent_id)
        if p.target_config:
            configs_set.add(p.target_config)
        if p.severity == "critical":
            critical += 1
        elif p.severity == "high":
            high += 1
        else:
            medium += 1

    summary = ConfigTamperSummary(
        total_patterns=len(patterns),
        by_type=dict(by_type),
        agents_involved=len(agents_set),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        configs_targeted=len(configs_set),
    )

    chains = _build_tamper_chains(patterns)

    return ConfigTamperReport(
        patterns=patterns,
        summary=summary,
        agents_involved=sorted(agents_set),
        tamper_chains=chains,
    )


def _detect_tamper_chains(patterns: list[ConfigTamperPattern]) -> None:
    by_agent: dict[str, list[ConfigTamperPattern]] = defaultdict(list)
    for p in patterns:
        if p.agent_id:
            by_agent[p.agent_id].append(p)

    for agent, agent_patterns in by_agent.items():
        types_seen = {p.tamper_type for p in agent_patterns}
        if "safety-mechanism-disable" in types_seen and "permission-escalation" in types_seen:
            for p in agent_patterns:
                if p.severity != "critical":
                    p.severity = "critical"


def _build_tamper_chains(patterns: list[ConfigTamperPattern]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    by_agent: dict[str, list[ConfigTamperPattern]] = defaultdict(list)
    for p in patterns:
        if p.agent_id:
            by_agent[p.agent_id].append(p)

    for agent, agent_patterns in by_agent.items():
        if len(agent_patterns) < 2:
            continue
        types_seen = sorted({p.tamper_type for p in agent_patterns})
        chains.append({
            "agent_id": agent,
            "pattern_count": len(agent_patterns),
            "tamper_types": types_seen,
            "first_seen": agent_patterns[0].timestamp,
            "last_seen": agent_patterns[-1].timestamp,
        })

    return chains


def format_text(report: ConfigTamperReport) -> str:
    lines: list[str] = []
    s = report.summary
    lines.append("=== Configuration Tampering Analysis ===")
    lines.append("")
    lines.append(f"Total patterns detected: {s.total_patterns}")
    lines.append(f"Agents involved:         {s.agents_involved}")
    lines.append(f"Configs targeted:        {s.configs_targeted}")
    lines.append(f"Critical: {s.critical_count}  High: {s.high_count}  Medium: {s.medium_count}")
    lines.append("")

    if s.by_type:
        lines.append("--- By Type ---")
        for t, c in sorted(s.by_type.items()):
            lines.append(f"  {t}: {c}")
        lines.append("")

    if report.patterns:
        lines.append("--- Patterns ---")
        for p in report.patterns:
            lines.append(
                f"  [{p.severity.upper()}] {p.tamper_type} | agent={p.agent_id} | "
                f"{p.evidence} | file={p.source_file}:{p.line}"
            )
        lines.append("")

    if report.tamper_chains:
        lines.append("--- Tamper Chains ---")
        for c in report.tamper_chains:
            lines.append(
                f"  Agent {c['agent_id']}: {c['pattern_count']} patterns, "
                f"types={c['tamper_types']}"
            )
        lines.append("")

    if s.total_patterns == 0:
        lines.append("No configuration tampering patterns detected.")
        lines.append("")

    return "\n".join(lines)


def format_json(report: ConfigTamperReport) -> str:
    data = {
        "summary": asdict(report.summary),
        "patterns": [asdict(p) for p in report.patterns],
        "agents_involved": report.agents_involved,
        "tamper_chains": report.tamper_chains,
    }
    return json.dumps(data, indent=2)
