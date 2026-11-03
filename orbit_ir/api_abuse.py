"""API abuse pattern detection for AI agent interactions.

Detects rate abuse, endpoint scraping, authentication bypass attempts,
parameter tampering, and excessive data extraction through API calls.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class AbuseDetection:
    detection_id: str
    agent_id: str
    abuse_type: str  # rate-abuse, endpoint-scrape, auth-bypass, param-tamper, data-extract
    severity: str  # critical, high, medium, low
    description: str
    evidence: list = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentAbuseScore:
    agent_id: str
    total_detections: int = 0
    risk_score: float = 0.0
    abuse_types: list = field(default_factory=list)


@dataclass
class AbuseSummary:
    total_detections: int = 0
    agents_involved: int = 0
    highest_severity: str = "none"
    endpoints_targeted: int = 0
    abuse_types: list = field(default_factory=list)


@dataclass
class AbuseReport:
    detections: List[AbuseDetection] = field(default_factory=list)
    agent_scores: List[AgentAbuseScore] = field(default_factory=list)
    summary: AbuseSummary = field(default_factory=AbuseSummary)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_RATE_THRESHOLD = 10  # calls to same endpoint in window
_SCRAPE_THRESHOLD = 8  # distinct endpoints in short window
_SENSITIVE_PARAMS = re.compile(
    r"(admin|root|sudo|token|key|secret|password|role|privilege|internal)",
    re.IGNORECASE,
)
_AUTH_BYPASS_PATTERNS = [
    "authorization: none",
    "x-api-key: ''",
    "bearer null",
    "bearer undefined",
    "cookie: ''",
    "auth: false",
]
_DATA_EXTRACT_KEYWORDS = [
    "limit=999", "limit=10000", "per_page=1000",
    "select=*", "fields=all", "export=true",
    "dump=true", "format=csv", "download=all",
]


def _next_id(counters: dict, prefix: str) -> str:
    counters[prefix] = counters.get(prefix, 0) + 1
    return f"{prefix}-{counters[prefix]:04d}"


def _detect_rate_abuse(events: list, counters: dict) -> list[AbuseDetection]:
    detections = []
    agent_endpoint: dict[tuple[str, str], list] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        endpoint = ev.get("endpoint", ev.get("resource", ""))
        if agent and endpoint:
            agent_endpoint[(agent, endpoint)].append(ev)
    for (agent, endpoint), calls in agent_endpoint.items():
        if len(calls) >= _RATE_THRESHOLD:
            detections.append(AbuseDetection(
                detection_id=_next_id(counters, "AA"),
                agent_id=agent,
                abuse_type="rate-abuse",
                severity="medium",
                description=f"Agent made {len(calls)} calls to {endpoint} (threshold: {_RATE_THRESHOLD})",
                evidence=[{"endpoint": endpoint, "call_count": len(calls)}],
                timestamp=calls[-1].get("timestamp", ""),
            ))
    return detections


def _detect_endpoint_scrape(events: list, counters: dict) -> list[AbuseDetection]:
    detections = []
    agent_endpoints: dict[str, set] = defaultdict(set)
    for ev in events:
        agent = ev.get("agent_id", "")
        endpoint = ev.get("endpoint", ev.get("resource", ""))
        if agent and endpoint:
            agent_endpoints[agent].add(endpoint)
    for agent, endpoints in agent_endpoints.items():
        if len(endpoints) >= _SCRAPE_THRESHOLD:
            detections.append(AbuseDetection(
                detection_id=_next_id(counters, "AA"),
                agent_id=agent,
                abuse_type="endpoint-scrape",
                severity="high",
                description=f"Agent probed {len(endpoints)} distinct endpoints (threshold: {_SCRAPE_THRESHOLD})",
                evidence=[{"endpoints": sorted(endpoints)[:10]}],
                timestamp=events[-1].get("timestamp", "") if events else "",
            ))
    return detections


def _detect_auth_bypass(events: list, counters: dict) -> list[AbuseDetection]:
    detections = []
    for ev in events:
        headers = ev.get("headers", {})
        if isinstance(headers, dict):
            header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        elif isinstance(headers, str):
            header_str = headers.lower()
        else:
            continue
        for pattern in _AUTH_BYPASS_PATTERNS:
            if pattern in header_str:
                detections.append(AbuseDetection(
                    detection_id=_next_id(counters, "AA"),
                    agent_id=ev.get("agent_id", "unknown"),
                    abuse_type="auth-bypass",
                    severity="critical",
                    description=f"Authentication bypass attempt: {pattern}",
                    evidence=[{"header_pattern": pattern, "endpoint": ev.get("endpoint", "")}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def _detect_param_tamper(events: list, counters: dict) -> list[AbuseDetection]:
    detections = []
    for ev in events:
        params = ev.get("params", ev.get("query_params", {}))
        if not params:
            continue
        if isinstance(params, str):
            param_str = params.lower()
        else:
            param_str = " ".join(f"{k}={v}" for k, v in params.items()).lower()
        if _SENSITIVE_PARAMS.search(param_str):
            detections.append(AbuseDetection(
                detection_id=_next_id(counters, "AA"),
                agent_id=ev.get("agent_id", "unknown"),
                abuse_type="param-tamper",
                severity="high",
                description=f"Sensitive parameter manipulation detected in API call",
                evidence=[{"params": params, "endpoint": ev.get("endpoint", "")}],
                timestamp=ev.get("timestamp", ""),
            ))
    return detections


def _detect_data_extract(events: list, counters: dict) -> list[AbuseDetection]:
    detections = []
    for ev in events:
        url = ev.get("url", ev.get("endpoint", ""))
        params = ev.get("params", ev.get("query_params", {}))
        search_str = url.lower()
        if isinstance(params, dict):
            search_str += " " + " ".join(f"{k}={v}" for k, v in params.items()).lower()
        elif isinstance(params, str):
            search_str += " " + params.lower()
        for keyword in _DATA_EXTRACT_KEYWORDS:
            if keyword in search_str:
                detections.append(AbuseDetection(
                    detection_id=_next_id(counters, "AA"),
                    agent_id=ev.get("agent_id", "unknown"),
                    abuse_type="data-extract",
                    severity="high",
                    description=f"Excessive data extraction: {keyword}",
                    evidence=[{"keyword": keyword, "endpoint": url}],
                    timestamp=ev.get("timestamp", ""),
                ))
                break
    return detections


def analyze_api_abuse(events: list) -> AbuseReport:
    if not events:
        return AbuseReport()

    counters: dict = {}
    detections: list[AbuseDetection] = []
    detections.extend(_detect_rate_abuse(events, counters))
    detections.extend(_detect_endpoint_scrape(events, counters))
    detections.extend(_detect_auth_bypass(events, counters))
    detections.extend(_detect_param_tamper(events, counters))
    detections.extend(_detect_data_extract(events, counters))

    agent_map: dict[str, AgentAbuseScore] = {}
    for d in detections:
        if d.agent_id not in agent_map:
            agent_map[d.agent_id] = AgentAbuseScore(agent_id=d.agent_id)
        s = agent_map[d.agent_id]
        s.total_detections += 1
        s.risk_score += _SEV_RANK.get(d.severity, 0)
        if d.abuse_type not in s.abuse_types:
            s.abuse_types.append(d.abuse_type)

    agents = sorted(agent_map.values(), key=lambda a: -a.risk_score)
    involved = set(d.agent_id for d in detections)
    endpoints = set()
    for ev in events:
        ep = ev.get("endpoint", ev.get("resource", ""))
        if ep:
            endpoints.add(ep)

    abuse_types = list(set(d.abuse_type for d in detections))
    highest = "none"
    for d in detections:
        if _SEV_RANK.get(d.severity, 0) > _SEV_RANK.get(highest, 0):
            highest = d.severity

    return AbuseReport(
        detections=detections,
        agent_scores=agents,
        summary=AbuseSummary(
            total_detections=len(detections),
            agents_involved=len(involved),
            highest_severity=highest,
            endpoints_targeted=len(endpoints),
            abuse_types=abuse_types,
        ),
    )


def format_text(report: AbuseReport) -> str:
    lines = [
        "API Abuse Detection Report",
        "=" * 62, "",
        f"  Total detections:    {report.summary.total_detections}",
        f"  Agents involved:     {report.summary.agents_involved}",
        f"  Highest severity:    {report.summary.highest_severity}",
        f"  Endpoints targeted:  {report.summary.endpoints_targeted}",
        "",
    ]
    if report.detections:
        lines.append("  Detections:")
        lines.append("  " + "-" * 60)
        for d in report.detections:
            lines.append(f"    [{d.detection_id}] {d.abuse_type} ({d.severity})")
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


def format_json(report: AbuseReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"


def _load_events(path: str) -> list:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return []
