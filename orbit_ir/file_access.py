"""Unauthorized file access pattern detection for AI agents.

Detects access to sensitive paths, credential files, configuration files,
system files, and private key access attempts.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List


@dataclass
class AccessDetection:
    detection_id: str
    agent_id: str
    access_type: str  # credential-file, system-config, private-key, sensitive-path, env-file
    severity: str
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentAccessScore:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    access_types: list = field(default_factory=list)


@dataclass
class AccessSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    files_targeted: int = 0
    access_types: list = field(default_factory=list)


@dataclass
class AccessReport:
    detections: List[AccessDetection] = field(default_factory=list)
    agent_scores: List[AgentAccessScore] = field(default_factory=list)
    summary: AccessSummary = field(default_factory=AccessSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_CREDENTIAL_FILES = [
    re.compile(r"\.aws/credentials$"),
    re.compile(r"\.aws/config$"),
    re.compile(r"\.docker/config\.json$"),
    re.compile(r"\.kube/config$"),
    re.compile(r"\.netrc$"),
    re.compile(r"\.npmrc$"),
    re.compile(r"\.pypirc$"),
    re.compile(r"credentials\.json$"),
    re.compile(r"service[_-]?account.*\.json$"),
    re.compile(r"token\.json$"),
]

_SYSTEM_CONFIG_FILES = [
    re.compile(r"/etc/passwd$"),
    re.compile(r"/etc/shadow$"),
    re.compile(r"/etc/sudoers$"),
    re.compile(r"/etc/hosts$"),
    re.compile(r"/proc/self/environ$"),
    re.compile(r"/proc/\d+/environ$"),
]

_PRIVATE_KEY_PATTERNS = [
    re.compile(r"\.pem$"),
    re.compile(r"id_rsa$"),
    re.compile(r"id_ed25519$"),
    re.compile(r"id_ecdsa$"),
    re.compile(r"\.key$"),
    re.compile(r"\.p12$"),
    re.compile(r"\.pfx$"),
    re.compile(r"\.ssh/.*$"),
]

_SENSITIVE_PATHS = [
    re.compile(r"/var/run/docker\.sock$"),
    re.compile(r"/run/secrets/"),
    re.compile(r"/proc/\d+/(cmdline|maps|mem|fd/)"),
    re.compile(r"/sys/kernel/"),
    re.compile(r"/dev/mem$"),
]

_ENV_FILE_PATTERNS = [
    re.compile(r"\.env$"),
    re.compile(r"\.env\.(local|production|staging|development)$"),
    re.compile(r"\.env\.\w+$"),
]


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _get_path(ev: dict) -> str:
    for key in ("path", "file", "resource", "target"):
        val = ev.get(key, "")
        if isinstance(val, str) and val:
            return val
    return ""


def _check_patterns(path: str, patterns: list, access_type: str, severity: str,
                    desc_prefix: str, ev: dict, counters: dict) -> list[AccessDetection]:
    detections = []
    for pattern in patterns:
        if pattern.search(path):
            detections.append(AccessDetection(
                detection_id=_next_id(counters, "FA"),
                agent_id=ev.get("agent_id", "unknown"),
                access_type=access_type,
                severity=severity,
                description=f"{desc_prefix}: {path}",
                evidence=[{"path": path, "pattern": pattern.pattern}],
                timestamp=ev.get("timestamp", ""),
            ))
            break
    return detections


def analyze_file_access(events: list) -> AccessReport:
    if not events:
        return AccessReport()

    counters: dict = {}
    detections: list[AccessDetection] = []
    files_seen = set()

    for ev in events:
        path = _get_path(ev)
        if not path:
            continue
        files_seen.add(path)

        detections.extend(_check_patterns(
            path, _CREDENTIAL_FILES, "credential-file", "critical",
            "Credential file access", ev, counters))
        detections.extend(_check_patterns(
            path, _SYSTEM_CONFIG_FILES, "system-config", "high",
            "System configuration access", ev, counters))
        detections.extend(_check_patterns(
            path, _PRIVATE_KEY_PATTERNS, "private-key", "critical",
            "Private key access", ev, counters))
        detections.extend(_check_patterns(
            path, _SENSITIVE_PATHS, "sensitive-path", "high",
            "Sensitive path access", ev, counters))
        detections.extend(_check_patterns(
            path, _ENV_FILE_PATTERNS, "env-file", "high",
            "Environment file access", ev, counters))

    agent_map: dict[str, AgentAccessScore] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentAccessScore(agent_id=d.agent_id)
        s = agent_map[d.agent_id]
        s.total_detections += 1
        s.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.access_type not in s.access_types:
            s.access_types.append(d.access_type)

    agents = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    access_types = list(set(d.access_type for d in detections))
    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return AccessReport(
        detections=detections,
        agent_scores=agents,
        summary=AccessSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            files_targeted=len(files_seen),
            access_types=access_types,
        ),
    )


def format_text(report: AccessReport) -> str:
    lines = [
        "File Access Detection Report",
        "=" * 62, "",
        f"  Total detections:    {report.summary.total_detections}",
        f"  Agents involved:     {report.summary.agents_involved}",
        f"  Highest severity:    {report.summary.highest_severity}",
        f"  Files targeted:      {report.summary.files_targeted}",
        "",
    ]
    if report.detections:
        lines.append("  Detections:")
        lines.append("  " + "-" * 60)
        for d in report.detections:
            lines.append(f"    [{d.detection_id}] {d.access_type} ({d.severity})")
            lines.append(f"      Agent: {d.agent_id}")
            lines.append(f"      {d.description}")
        lines.append("")
    if report.agent_scores:
        lines.append("  Agent Risk Scores:")
        lines.append("  " + "-" * 60)
        for a in report.agent_scores:
            lines.append(f"    {a.agent_id}: score={a.risk_score:.1f} detections={a.total_detections}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: AccessReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
