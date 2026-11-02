"""API key and secret leakage detection for agent evidence.

Analyzes agent evidence for API key and credential leakage — agents
exposing API keys, bearer tokens, passwords, connection strings,
private keys, or credentials in URLs through their outputs or logs.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


API_KEY_PATTERNS = re.compile(
    r"(AKIA[0-9A-Z]{16}|"  # AWS access key
    r"AIza[0-9A-Za-z\-_]{35}|"  # GCP API key
    r"sk-[A-Za-z0-9]{20,}|"  # OpenAI API key
    r"ghp_[A-Za-z0-9]{36}|"  # GitHub PAT
    r"ghs_[A-Za-z0-9]{36}|"  # GitHub App token
    r"xox[bpras]-[A-Za-z0-9\-]{10,}|"  # Slack token
    r"sq0[a-z]{3}-[A-Za-z0-9\-_]{22,})",  # Square
)

BEARER_TOKEN_PATTERN = re.compile(
    r"(?:Authorization|Bearer)\s*[:=]\s*Bearer\s+[A-Za-z0-9\-_.~+/]+=*",
    re.IGNORECASE,
)

PASSWORD_PLAINTEXT_PATTERN = re.compile(
    r"(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
    re.IGNORECASE,
)

CONNECTION_STRING_PATTERN = re.compile(
    r"(?:mongodb|postgres|mysql|redis|amqp|mssql)://[^\s]+:[^\s]+@[^\s]+",
    re.IGNORECASE,
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC)\s+KEY-----",
    re.IGNORECASE,
)

CREDENTIAL_URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9._~%!$&'()*+,;=\-]+:[A-Za-z0-9._~%!$&'()*+,;=\-]+@[^\s]+",
)


@dataclass
class ApiKeyLeakFinding:
    agent_id: str
    pattern: str
    leaked_type: str
    timestamp: str
    confidence: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApiKeyLeakSummary:
    total_findings: int
    api_key_in_output: int
    bearer_token_exposure: int
    password_in_plaintext: int
    connection_string_leak: int
    private_key_material: int
    credential_in_url: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class ApiKeyLeakReport:
    findings: list[ApiKeyLeakFinding]
    summary: ApiKeyLeakSummary
    agents_involved: list[str]


def _extract_output(ev: dict[str, Any]) -> str:
    for k in ("output", "response", "result", "content", "message", "text", "log"):
        val = ev.get(k, "")
        if val:
            return str(val)
    return ""


def _has_output(ev: dict[str, Any]) -> bool:
    return len(_extract_output(ev)) > 10


def _redact(s: str, keep: int = 6) -> str:
    if len(s) <= keep:
        return s
    return s[:keep] + "..." + ("*" * min(8, len(s) - keep))


def analyze_api_key_leaks(events: list[dict[str, Any]]) -> ApiKeyLeakReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        if _has_output(ev):
            agent_events[agent].append(ev)

    findings: list[ApiKeyLeakFinding] = []

    for agent, evs in sorted(agent_events.items()):
        evs.sort(key=lambda e: e.get("timestamp", ""))
        _detect_api_keys(agent, evs, findings)
        _detect_bearer_tokens(agent, evs, findings)
        _detect_passwords(agent, evs, findings)
        _detect_connection_strings(agent, evs, findings)
        _detect_private_keys(agent, evs, findings)
        _detect_credential_urls(agent, evs, findings)

    all_agents = sorted({f.agent_id for f in findings})
    conf: dict[str, int] = defaultdict(int)
    pattern_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        conf[f.confidence] += 1
        pattern_counts[f.pattern] += 1

    return ApiKeyLeakReport(
        findings=findings,
        summary=ApiKeyLeakSummary(
            total_findings=len(findings),
            api_key_in_output=pattern_counts.get("api_key_in_output", 0),
            bearer_token_exposure=pattern_counts.get("bearer_token_exposure", 0),
            password_in_plaintext=pattern_counts.get("password_in_plaintext", 0),
            connection_string_leak=pattern_counts.get("connection_string_leak", 0),
            private_key_material=pattern_counts.get("private_key_material", 0),
            credential_in_url=pattern_counts.get("credential_in_url", 0),
            agents_involved=len(all_agents),
            by_confidence=dict(conf),
        ),
        agents_involved=all_agents,
    )


def _detect_api_keys(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        match = API_KEY_PATTERNS.search(output)
        if match:
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="api_key_in_output",
                leaked_type="api_key",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed API key in output: {_redact(match.group())}",
                evidence={"redacted_key": _redact(match.group())},
            ))


def _detect_bearer_tokens(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        if BEARER_TOKEN_PATTERN.search(output):
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="bearer_token_exposure",
                leaked_type="bearer_token",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed Bearer token in output",
                evidence={},
            ))


def _detect_passwords(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        match = PASSWORD_PLAINTEXT_PATTERN.search(output)
        if match:
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="password_in_plaintext",
                leaked_type="password",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed password/secret in plaintext",
                evidence={"matched_pattern": match.group().split("=")[0].split(":")[0].strip()},
            ))


def _detect_connection_strings(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        match = CONNECTION_STRING_PATTERN.search(output)
        if match:
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="connection_string_leak",
                leaked_type="connection_string",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed database connection string with credentials",
                evidence={"db_type": match.group().split("://")[0]},
            ))


def _detect_private_keys(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        if PRIVATE_KEY_PATTERN.search(output):
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="private_key_material",
                leaked_type="private_key",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed private key material in output",
                evidence={},
            ))


def _detect_credential_urls(agent: str, events: list[dict[str, Any]], findings: list[ApiKeyLeakFinding]) -> None:
    for ev in events:
        output = _extract_output(ev)
        match = CREDENTIAL_URL_PATTERN.search(output)
        if match:
            findings.append(ApiKeyLeakFinding(
                agent_id=agent,
                pattern="credential_in_url",
                leaked_type="url_credential",
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' exposed credentials embedded in URL",
                evidence={},
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


def format_text(report: ApiKeyLeakReport) -> str:
    lines: list[str] = []
    lines.append("API Key Leak Detection Report")
    lines.append("=" * 62)
    lines.append("")
    s = report.summary
    lines.append(f"  Total findings:          {s.total_findings}")
    lines.append(f"  API keys in output:      {s.api_key_in_output}")
    lines.append(f"  Bearer token exposure:   {s.bearer_token_exposure}")
    lines.append(f"  Passwords in plaintext:  {s.password_in_plaintext}")
    lines.append(f"  Connection string leaks: {s.connection_string_leak}")
    lines.append(f"  Private key material:    {s.private_key_material}")
    lines.append(f"  Credentials in URLs:     {s.credential_in_url}")
    lines.append(f"  Agents involved:         {s.agents_involved}")
    lines.append("")
    if report.findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 58)
        for f in report.findings:
            lines.append(f"    [{f.confidence.upper()}] {f.pattern}: {f.agent_id}")
            lines.append(f"      {f.description}")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_json(report: ApiKeyLeakReport) -> str:
    data = {
        "findings": [asdict(f) for f in report.findings],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
