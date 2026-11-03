"""Token and credential exfiltration detection in agent evidence.

Identifies attempts to extract, transmit, or stage authentication tokens,
API keys, credentials, session cookies, and other secrets from agent
environments to external or unauthorized destinations.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


TOKEN_EXTRACTION_KEYWORDS = {
    "api key", "api_key", "apikey", "access token", "access_token",
    "secret key", "secret_key", "auth token", "bearer token",
    "jwt", "session token", "refresh token", "oauth token",
    "private key", "ssh key", "signing key",
}

CREDENTIAL_HARVEST_KEYWORDS = {
    "password", "passwd", "credentials", "login", "auth",
    "username", "user_pass", "db_password", "database_url",
    "connection string", "connection_string",
}

EXFIL_CHANNEL_KEYWORDS = {
    "curl", "wget", "http post", "requests.post", "fetch(",
    "webhook", "exfiltrate", "send to", "upload to",
    "base64 encode", "base64encode", "b64encode",
    "dns tunnel", "dns query", "nslookup",
}

ENV_DUMP_KEYWORDS = {
    "env", "environ", "os.environ", "process.env", "printenv",
    "env vars", "environment variable", "dotenv", ".env",
    "aws_secret", "aws_access", "azure_key", "gcp_key",
}

STAGING_KEYWORDS = {
    "write to file", "save to", "store in", "dump to",
    "copy to", "move to", "stage", "stash",
    "clipboard", "temp file", "tmp file",
}

TOKEN_EXFIL_TYPES = {
    "token-extraction",
    "credential-harvest",
    "exfil-channel",
    "env-dump",
    "credential-staging",
}


@dataclass
class TokenExfilPattern:
    timestamp: str
    agent_id: str
    event_id: str
    exfil_type: str
    evidence: str
    target: str
    technique: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class TokenExfilSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    targets_identified: int = 0


@dataclass
class TokenExfilReport:
    patterns: list[TokenExfilPattern]
    summary: TokenExfilSummary
    agents_involved: list[str]
    exfil_chains: list[dict[str, Any]] = field(default_factory=list)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_token_extraction(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, TOKEN_EXTRACTION_KEYWORDS)
    if matches:
        return True, matches, f"Token extraction: {', '.join(matches)}"
    return False, [], ""


def _detect_credential_harvest(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, CREDENTIAL_HARVEST_KEYWORDS)
    if matches:
        return True, matches, f"Credential harvest: {', '.join(matches)}"
    return False, [], ""


def _detect_exfil_channel(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, EXFIL_CHANNEL_KEYWORDS)
    if matches:
        return True, matches, f"Exfiltration channel: {', '.join(matches)}"
    return False, [], ""


def _detect_env_dump(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, ENV_DUMP_KEYWORDS)
    if matches:
        return True, matches, f"Environment dump: {', '.join(matches)}"
    return False, [], ""


def _detect_credential_staging(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, STAGING_KEYWORDS)
    if matches:
        return True, matches, f"Credential staging: {', '.join(matches)}"
    return False, [], ""


def _classify_severity(exfil_type: str, matches: list[str]) -> str:
    if exfil_type in ("token-extraction", "exfil-channel"):
        return "critical" if len(matches) >= 2 else "high"
    if exfil_type == "credential-harvest":
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


def _detect_exfil_chains(patterns: list[TokenExfilPattern]) -> list[dict[str, Any]]:
    agent_types: dict[str, set[str]] = defaultdict(set)
    for p in patterns:
        if p.agent_id:
            agent_types[p.agent_id].add(p.exfil_type)

    chains: list[dict[str, Any]] = []
    for agent, types in agent_types.items():
        if ("token-extraction" in types or "credential-harvest" in types) and \
           ("exfil-channel" in types or "credential-staging" in types):
            chains.append({
                "agent": agent,
                "types": sorted(types),
                "severity": "critical",
                "description": f"Agent '{agent}' shows both credential access and exfiltration channel",
            })
            for p in patterns:
                if p.agent_id == agent:
                    p.severity = "critical"

    return chains


def _build_exfil_chains(patterns: list[TokenExfilPattern]) -> list[dict[str, Any]]:
    return _detect_exfil_chains(patterns)


def analyze_token_exfil(
    events: list[dict[str, Any]],
    control_events: list[dict[str, Any]] | None = None,
) -> TokenExfilReport:
    if control_events is None:
        control_events = []

    patterns: list[TokenExfilPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("token-extraction", _detect_token_extraction),
        ("credential-harvest", _detect_credential_harvest),
        ("exfil-channel", _detect_exfil_channel),
        ("env-dump", _detect_env_dump),
        ("credential-staging", _detect_credential_staging),
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
            target = ev.get("target", ev.get("destination", ev.get("url", "")))
            technique = ev.get("technique", "")

            for exfil_type, detector in detectors:
                found, matches, desc = detector(ev)
                if not found:
                    continue
                dedup = (agent, exfil_type, eid)
                if dedup in seen:
                    continue
                seen.add(dedup)

                sev = _classify_severity(exfil_type, matches)
                patterns.append(TokenExfilPattern(
                    timestamp=ts,
                    agent_id=agent,
                    event_id=eid,
                    exfil_type=exfil_type,
                    evidence=desc,
                    target=target,
                    technique=technique,
                    source_file=source_file,
                    line=i + 1,
                    severity=sev,
                    matched_keywords=matches,
                ))

    exfil_chains = _build_exfil_chains(patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents_set: set[str] = set()
    targets_set: set[str] = set()
    critical = high = medium = 0

    for p in patterns:
        by_type[p.exfil_type] += 1
        if p.agent_id:
            agents_set.add(p.agent_id)
        if p.target:
            targets_set.add(p.target)
        if p.severity == "critical":
            critical += 1
        elif p.severity == "high":
            high += 1
        else:
            medium += 1

    summary = TokenExfilSummary(
        total_patterns=len(patterns),
        by_type=dict(by_type),
        agents_involved=len(agents_set),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        targets_identified=len(targets_set),
    )

    return TokenExfilReport(
        patterns=patterns,
        summary=summary,
        agents_involved=sorted(agents_set),
        exfil_chains=exfil_chains,
    )


def format_text(report: TokenExfilReport) -> str:
    lines = [
        f"Token Exfiltration Analysis ({report.summary.total_patterns} patterns found)",
        "",
        f"  Agents involved:     {report.summary.agents_involved}",
        f"  Critical findings:   {report.summary.critical_count}",
        f"  High findings:       {report.summary.high_count}",
        f"  Medium findings:     {report.summary.medium_count}",
        f"  Targets identified:  {report.summary.targets_identified}",
        "",
    ]

    if report.summary.by_type:
        lines.append("  By type:")
        for t, c in sorted(report.summary.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    if report.exfil_chains:
        lines.append("  Exfiltration chains:")
        for ch in report.exfil_chains:
            lines.append(f"    [{ch['severity']}] {ch['description']}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity}] {p.exfil_type} | agent={p.agent_id} | {p.evidence}")
        if p.target:
            lines.append(f"    target: {p.target}")
        lines.append(f"    file: {p.source_file}:{p.line}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: TokenExfilReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str)
