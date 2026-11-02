"""Resource hijacking detection in agent evidence.

Identifies agents diverting compute, memory, storage, network bandwidth,
or API quota for unauthorized purposes: cryptomining, DDoS participation,
unauthorized data processing, and resource exhaustion attacks.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CRYPTO_KEYWORDS = {
    "mine", "miner", "mining", "hashrate", "hash rate", "xmrig",
    "stratum", "pool", "nonce", "proof of work", "coinbase",
    "monero", "bitcoin", "ethereum", "wallet", "crypto",
}

DDOS_KEYWORDS = {
    "flood", "ddos", "dos attack", "syn flood", "amplification",
    "reflection attack", "botnet", "slowloris", "stress test",
    "volumetric", "layer 7 attack",
}

RESOURCE_EXHAUST_KEYWORDS = {
    "fork bomb", "memory leak", "oom", "out of memory",
    "cpu spike", "disk full", "no space left", "resource limit",
    "quota exceeded", "rate limit exceeded", "throttled",
    "max connections", "connection pool exhausted",
}

UNAUTHORIZED_COMPUTE_KEYWORDS = {
    "unauthorized process", "rogue process", "hidden service",
    "background task", "sidecar", "shadow compute", "piggyback",
    "covert channel", "tunnel", "proxy chain", "reverse shell",
}

HIJACK_TYPES = {
    "cryptomining",
    "ddos-participation",
    "resource-exhaustion",
    "unauthorized-compute",
    "bandwidth-abuse",
    "quota-theft",
}


@dataclass
class ResourceHijackPattern:
    timestamp: str
    agent_id: str
    event_id: str
    hijack_type: str
    evidence: str
    resource: str
    target: str
    source_file: str
    line: int
    severity: str
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class ResourceHijackSummary:
    total_patterns: int
    by_type: dict[str, int] = field(default_factory=dict)
    agents_hijacking: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    resources_targeted: int = 0


@dataclass
class ResourceHijackReport:
    patterns: list[ResourceHijackPattern]
    summary: ResourceHijackSummary
    agents_involved: list[str]
    resource_map: dict[str, list[str]] = field(default_factory=dict)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(k for k in keyword_set if k in lower)


def _detect_cryptomining(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    args = json.dumps(event.get("args", {})) if event.get("args") else ""
    full_text = content + " " + args
    matches = _match_keywords(full_text, CRYPTO_KEYWORDS)
    if matches:
        return True, matches, f"Cryptomining indicators: {', '.join(matches)}"
    return False, [], ""


def _detect_ddos(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    matches = _match_keywords(content, DDOS_KEYWORDS)
    if matches:
        return True, matches, f"DDoS participation indicators: {', '.join(matches)}"
    return False, [], ""


def _detect_resource_exhaustion(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    error = event.get("error", "")
    full_text = content + " " + error
    matches = _match_keywords(full_text, RESOURCE_EXHAUST_KEYWORDS)
    if matches:
        return True, matches, f"Resource exhaustion: {', '.join(matches)}"
    return False, [], ""


def _detect_unauthorized_compute(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    content = event.get("content", "") + " " + event.get("message", "")
    tool = event.get("tool", "")
    full_text = content + " " + tool
    matches = _match_keywords(full_text, UNAUTHORIZED_COMPUTE_KEYWORDS)
    if matches:
        return True, matches, f"Unauthorized compute: {', '.join(matches)}"
    return False, [], ""


def _detect_bandwidth_abuse(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    bytes_sent = event.get("bytes_sent", 0)
    bytes_recv = event.get("bytes_received", 0)
    indicators: list[str] = []
    if isinstance(bytes_sent, (int, float)) and bytes_sent > 100_000_000:
        indicators.append(f"large-upload:{bytes_sent}")
    if isinstance(bytes_recv, (int, float)) and bytes_recv > 100_000_000:
        indicators.append(f"large-download:{bytes_recv}")
    connections = event.get("connection_count", 0)
    if isinstance(connections, (int, float)) and connections > 1000:
        indicators.append(f"many-connections:{connections}")
    if indicators:
        return True, indicators, f"Bandwidth abuse: {', '.join(indicators)}"
    return False, [], ""


def _detect_quota_theft(event: dict[str, Any]) -> tuple[bool, list[str], str]:
    indicators: list[str] = []
    tokens_used = event.get("tokens_used", 0)
    api_calls = event.get("api_call_count", 0)
    if isinstance(tokens_used, (int, float)) and tokens_used > 500_000:
        indicators.append(f"excessive-tokens:{tokens_used}")
    if isinstance(api_calls, (int, float)) and api_calls > 100:
        indicators.append(f"excessive-api-calls:{api_calls}")
    if event.get("unauthorized_model"):
        indicators.append(f"unauthorized-model:{event['unauthorized_model']}")
    if indicators:
        return True, indicators, f"Quota theft: {', '.join(indicators)}"
    return False, [], ""


def _classify_severity(hijack_type: str, matches: list[str]) -> str:
    if hijack_type in ("cryptomining", "ddos-participation"):
        return "critical"
    if len(matches) >= 3:
        return "high"
    if hijack_type == "unauthorized-compute":
        return "high"
    if len(matches) >= 2:
        return "medium"
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
) -> ResourceHijackReport:
    if control_events is None:
        control_events = []

    patterns: list[ResourceHijackPattern] = []
    seen: set[tuple[str, str, str]] = set()

    detectors = [
        ("cryptomining", _detect_cryptomining),
        ("ddos-participation", _detect_ddos),
        ("resource-exhaustion", _detect_resource_exhaustion),
        ("unauthorized-compute", _detect_unauthorized_compute),
        ("bandwidth-abuse", _detect_bandwidth_abuse),
        ("quota-theft", _detect_quota_theft),
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
            resource = ev.get("resource", "")
            target = ev.get("target", ev.get("target_agent", ""))

            for hijack_type, detector in detectors:
                found, matches, evidence = detector(ev)
                if found:
                    key = (agent, eid, hijack_type)
                    if key not in seen:
                        seen.add(key)
                        sev = _classify_severity(hijack_type, matches)
                        patterns.append(ResourceHijackPattern(
                            timestamp=ts,
                            agent_id=agent,
                            event_id=eid,
                            hijack_type=hijack_type,
                            evidence=evidence,
                            resource=resource,
                            target=target,
                            source_file=source_file,
                            line=i + 1,
                            severity=sev,
                            matched_keywords=matches,
                        ))

    patterns.sort(key=lambda p: ({"critical": 0, "high": 1, "medium": 2}.get(p.severity, 3), p.timestamp))

    hijackers = sorted({p.agent_id for p in patterns})
    resources = sorted({p.resource for p in patterns if p.resource})

    by_type: dict[str, int] = defaultdict(int)
    crit = high = med = 0
    resource_map: dict[str, list[str]] = defaultdict(list)
    for p in patterns:
        by_type[p.hijack_type] += 1
        if p.severity == "critical":
            crit += 1
        elif p.severity == "high":
            high += 1
        else:
            med += 1
        if p.resource and p.agent_id not in resource_map[p.resource]:
            resource_map[p.resource].append(p.agent_id)

    return ResourceHijackReport(
        patterns=patterns,
        summary=ResourceHijackSummary(
            total_patterns=len(patterns),
            by_type=dict(by_type),
            agents_hijacking=len(hijackers),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            resources_targeted=len(resources),
        ),
        agents_involved=hijackers,
        resource_map=dict(resource_map),
    )


def format_text(report: ResourceHijackReport) -> str:
    lines: list[str] = []
    lines.append("Resource Hijacking Detection")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total patterns:       {s.total_patterns}")
    lines.append(f"  Agents hijacking:     {s.agents_hijacking}")
    lines.append(f"  Resources targeted:   {s.resources_targeted}")
    lines.append(f"  Critical:             {s.critical_count}")
    lines.append(f"  High:                 {s.high_count}")
    lines.append(f"  Medium:               {s.medium_count}")
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
            lines.append(f"  [{sev_tag}] {p.hijack_type}: {p.agent_id}")
            lines.append(f"    {p.evidence}")
            if p.resource:
                lines.append(f"    Resource: {p.resource}")
            if p.target:
                lines.append(f"    Target: {p.target}")
            lines.append(f"    Time: {p.timestamp}  Source: {p.source_file}:{p.line}")
            lines.append("")

    if report.resource_map:
        lines.append("  Resource Map:")
        lines.append("  " + "-" * 60)
        for resource, agents in sorted(report.resource_map.items()):
            lines.append(f"    {resource}: {', '.join(agents)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ResourceHijackReport) -> str:
    data = {
        "patterns": [asdict(p) for p in report.patterns],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "resource_map": report.resource_map,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
