"""Shadow API detection for agent evidence.

Analyzes agent evidence for shadow API usage — agents accessing
undocumented, deprecated, debug, or internal API endpoints that bypass
normal access controls. Detects hidden parameters, version mismatches,
and unauthorized internal endpoint access.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DEBUG_PATTERNS = re.compile(
    r"(/debug[/_-]|/\.debug|/_debug|/internal/debug|/admin/debug|"
    r"\bdebug=true\b|\bdebug_mode=)",
    re.IGNORECASE,
)

DEPRECATED_PATTERNS = re.compile(
    r"(/v0/|/v1/|/api/v0/|/legacy/|/deprecated/|/old-api/|"
    r"X-Deprecated|api[-_]?version\s*[:=]\s*['\"]?0)",
    re.IGNORECASE,
)

INTERNAL_PATTERNS = re.compile(
    r"(/internal/|/_internal/|/private/|/__private/|/backstage/|"
    r"/staff[-_]only/|/admin[-_]api/|10\.\d+\.\d+\.\d+|"
    r"127\.0\.0\.\d+|localhost:\d+|\.internal\.|\.local:)",
    re.IGNORECASE,
)

HIDDEN_PARAM_PATTERNS = re.compile(
    r"(__admin|__debug|__bypass|__override|__secret|__token|__key|"
    r"_hidden_|_internal_|x[-_]override|x[-_]bypass|x[-_]admin)",
    re.IGNORECASE,
)

VERSION_MISMATCH_PAIRS = [
    (re.compile(r"/v(\d+)/", re.IGNORECASE), "path_version"),
    (re.compile(r"api[-_]?version\s*[:=]\s*['\"]?(\d+)", re.IGNORECASE), "param_version"),
]

UNDOCUMENTED_INDICATORS = re.compile(
    r"(404\s+not\s+found.*fallback|undocumented|no[-_]?docs|"
    r"swagger[-_]?hidden|openapi[-_]?exclude|x[-_]hidden[-_]endpoint)",
    re.IGNORECASE,
)

VOLUME_THRESHOLD = 20


@dataclass
class ShadowApiFinding:
    agent_id: str
    pattern: str
    endpoint: str
    timestamp: str
    confidence: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ShadowApiSummary:
    total_findings: int
    undocumented_endpoint: int
    debug_api: int
    deprecated_api: int
    internal_api: int
    version_mismatch: int
    hidden_parameter: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class ShadowApiReport:
    findings: list[ShadowApiFinding]
    summary: ShadowApiSummary
    agents_involved: list[str]


def _extract_endpoint(ev: dict[str, Any]) -> str:
    for k in ("resource", "target", "url", "endpoint", "path"):
        val = ev.get(k, "")
        if val:
            return str(val)
    return ""


def _is_api_event(ev: dict[str, Any]) -> bool:
    tool = str(ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))).lower()
    endpoint = _extract_endpoint(ev).lower()
    if any(k in tool for k in ("http", "fetch", "request", "api", "curl", "wget", "invoke")):
        return True
    if any(k in endpoint for k in ("http://", "https://", "/api/", "/v1/", "/v2/")):
        return True
    return False


def analyze_shadow_apis(events: list[dict[str, Any]]) -> ShadowApiReport:
    agent_api: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        if _is_api_event(ev):
            agent_api[agent].append(ev)

    findings: list[ShadowApiFinding] = []

    for agent, api_events in sorted(agent_api.items()):
        api_events.sort(key=lambda e: e.get("timestamp", ""))
        _detect_debug_api(agent, api_events, findings)
        _detect_deprecated_api(agent, api_events, findings)
        _detect_internal_api(agent, api_events, findings)
        _detect_hidden_params(agent, api_events, findings)
        _detect_version_mismatch(agent, api_events, findings)
        _detect_undocumented(agent, api_events, findings)

    all_agents = sorted({f.agent_id for f in findings})
    conf: dict[str, int] = defaultdict(int)
    pattern_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        conf[f.confidence] += 1
        pattern_counts[f.pattern] += 1

    return ShadowApiReport(
        findings=findings,
        summary=ShadowApiSummary(
            total_findings=len(findings),
            undocumented_endpoint=pattern_counts.get("shadow_undocumented_endpoint", 0),
            debug_api=pattern_counts.get("shadow_debug_api", 0),
            deprecated_api=pattern_counts.get("shadow_deprecated_api", 0),
            internal_api=pattern_counts.get("shadow_internal_api", 0),
            version_mismatch=pattern_counts.get("shadow_version_mismatch", 0),
            hidden_parameter=pattern_counts.get("shadow_hidden_parameter", 0),
            agents_involved=len(all_agents),
            by_confidence=dict(conf),
        ),
        agents_involved=all_agents,
    )


def _detect_debug_api(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        if DEBUG_PATTERNS.search(endpoint):
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_debug_api",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' accessed debug API endpoint: {endpoint}",
                evidence={"endpoint": endpoint},
            ))


def _detect_deprecated_api(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        if DEPRECATED_PATTERNS.search(endpoint):
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_deprecated_api",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' accessed deprecated API endpoint: {endpoint}",
                evidence={"endpoint": endpoint},
            ))


def _detect_internal_api(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        if INTERNAL_PATTERNS.search(endpoint):
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_internal_api",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' accessed internal/private API endpoint: {endpoint}",
                evidence={"endpoint": endpoint},
            ))


def _detect_hidden_params(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        params = str(ev.get("parameters", ev.get("params", ev.get("headers", ""))))
        combined = endpoint + " " + params
        match = HIDDEN_PARAM_PATTERNS.search(combined)
        if match:
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_hidden_parameter",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' used hidden/internal parameter '{match.group()}': {endpoint}",
                evidence={"endpoint": endpoint, "hidden_param": match.group()},
            ))


def _detect_version_mismatch(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        params = str(ev.get("parameters", ev.get("params", "")))
        combined = endpoint + " " + params
        versions: dict[str, str] = {}
        for pat, label in VERSION_MISMATCH_PAIRS:
            m = pat.search(combined)
            if m:
                versions[label] = m.group(1)
        if len(versions) >= 2 and len(set(versions.values())) > 1:
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_version_mismatch",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' API version mismatch — path vs parameter: {endpoint}",
                evidence={"endpoint": endpoint, "versions": versions},
            ))


def _detect_undocumented(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[ShadowApiFinding],
) -> None:
    for ev in events:
        endpoint = _extract_endpoint(ev)
        response = str(ev.get("response", ev.get("result", ev.get("output", ""))))
        combined = endpoint + " " + response
        if UNDOCUMENTED_INDICATORS.search(combined):
            findings.append(ShadowApiFinding(
                agent_id=agent,
                pattern="shadow_undocumented_endpoint",
                endpoint=endpoint,
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' accessed undocumented endpoint: {endpoint}",
                evidence={"endpoint": endpoint},
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


def format_text(report: ShadowApiReport) -> str:
    lines: list[str] = []
    lines.append("Shadow API Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total findings:          {s.total_findings}")
    lines.append(f"  Undocumented endpoints:  {s.undocumented_endpoint}")
    lines.append(f"  Debug APIs:              {s.debug_api}")
    lines.append(f"  Deprecated APIs:         {s.deprecated_api}")
    lines.append(f"  Internal APIs:           {s.internal_api}")
    lines.append(f"  Version mismatches:      {s.version_mismatch}")
    lines.append(f"  Hidden parameters:       {s.hidden_parameter}")
    lines.append(f"  Agents involved:         {s.agents_involved}")
    lines.append("")

    if report.findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 58)
        for f in report.findings:
            lines.append(f"    [{f.confidence.upper()}] {f.pattern}: {f.agent_id}")
            lines.append(f"      {f.description}")
            lines.append(f"      Endpoint: {f.endpoint}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ShadowApiReport) -> str:
    data = {
        "findings": [asdict(f) for f in report.findings],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
