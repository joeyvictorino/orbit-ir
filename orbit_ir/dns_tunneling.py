"""DNS tunneling detection for agent evidence.

Analyzes agent event sequences to detect DNS-based data exfiltration
and covert communication—unusually long subdomains, high query volumes
to single domains, TXT record abuse, and encoded payloads in DNS labels.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DNS_TOOLS = {
    "dns_lookup", "resolve_host", "dns_query", "nslookup",
    "dig", "dns_resolve", "resolve", "lookup_host",
}

TXT_INDICATORS = {"txt", "text", "dns_txt", "txt_record"}

ENCODING_PATTERNS = [
    re.compile(r"[A-Za-z0-9+/]{30,}={0,2}"),  # base64-like
    re.compile(r"[0-9a-f]{32,}"),               # hex-like
    re.compile(r"[a-z0-9]{63}"),                 # max-length label
]

SUSPICIOUS_TLDS = {
    ".duckdns.org", ".no-ip.org", ".ddns.net", ".hopto.org",
    ".zapto.org", ".sytes.net", ".servequake.com",
}


@dataclass
class DNSTunnelDetection:
    agent_id: str
    domain: str
    query_count: int
    unique_subdomains: int
    avg_subdomain_length: float
    max_subdomain_length: int
    has_encoding: bool
    record_types: list[str]
    confidence: str
    description: str


@dataclass
class HighVolumeQuery:
    agent_id: str
    domain: str
    query_count: int
    time_span_seconds: float
    queries_per_minute: float
    first_seen: str
    last_seen: str
    confidence: str


@dataclass
class SuspiciousDNS:
    agent_id: str
    query: str
    reason: str
    timestamp: str
    tool: str


@dataclass
class DNSTunnelSummary:
    total_tunnel_detections: int
    total_high_volume: int
    total_suspicious: int
    agents_involved: int
    by_confidence: dict[str, int]
    domains_flagged: int


@dataclass
class DNSTunnelReport:
    tunnel_detections: list[DNSTunnelDetection]
    high_volume_queries: list[HighVolumeQuery]
    suspicious_queries: list[SuspiciousDNS]
    summary: DNSTunnelSummary
    agents_involved: list[str]


def _parse_ts(ts: str):
    if not ts:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_dns_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in DNS_TOOLS or any(k in lower for k in {"dns", "resolve", "nslookup", "lookup_host"})


def _extract_domain(query: str) -> str:
    query = query.strip().rstrip(".")
    parts = query.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return query


def _extract_subdomains(query: str) -> list[str]:
    query = query.strip().rstrip(".")
    parts = query.split(".")
    if len(parts) > 2:
        return parts[:-2]
    return []


def _has_encoded_labels(subdomains: list[str]) -> bool:
    for sub in subdomains:
        for pat in ENCODING_PATTERNS:
            if pat.search(sub):
                return True
    return False


def _is_suspicious_tld(query: str) -> bool:
    lower = query.lower()
    return any(lower.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _avg_length(items: list[str]) -> float:
    if not items:
        return 0.0
    return round(sum(len(s) for s in items) / len(items), 2)


def analyze_dns_tunneling(events: list[dict[str, Any]]) -> DNSTunnelReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    tunnel_detections: list[DNSTunnelDetection] = []
    high_volume: list[HighVolumeQuery] = []
    suspicious: list[SuspiciousDNS] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        _detect_tunnels(agent, evts_sorted, tunnel_detections)
        _detect_high_volume(agent, evts_sorted, high_volume)
        _detect_suspicious(agent, evts_sorted, suspicious)

    all_agents = set()
    conf_counts: dict[str, int] = defaultdict(int)
    for d in tunnel_detections:
        all_agents.add(d.agent_id)
        conf_counts[d.confidence] += 1
    for hv in high_volume:
        all_agents.add(hv.agent_id)
        conf_counts[hv.confidence] += 1
    for sq in suspicious:
        all_agents.add(sq.agent_id)

    domains_flagged = len({d.domain for d in tunnel_detections} | {hv.domain for hv in high_volume})

    return DNSTunnelReport(
        tunnel_detections=tunnel_detections,
        high_volume_queries=high_volume,
        suspicious_queries=suspicious,
        summary=DNSTunnelSummary(
            total_tunnel_detections=len(tunnel_detections),
            total_high_volume=len(high_volume),
            total_suspicious=len(suspicious),
            agents_involved=len(all_agents),
            by_confidence=dict(conf_counts),
            domains_flagged=domains_flagged,
        ),
        agents_involved=sorted(all_agents),
    )


def _detect_tunnels(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DNSTunnelDetection],
) -> None:
    domain_queries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_dns_tool(tool):
            continue
        query = ev.get("resource", ev.get("query", ev.get("domain", "")))
        if not query:
            continue
        domain = _extract_domain(query)
        domain_queries[domain].append(ev)

    for domain, evts in domain_queries.items():
        all_subdomains: list[str] = []
        record_types: set[str] = set()
        for ev in evts:
            query = ev.get("resource", ev.get("query", ev.get("domain", "")))
            subs = _extract_subdomains(query)
            all_subdomains.extend(subs)
            rtype = ev.get("record_type", ev.get("type", "")).upper()
            if rtype:
                record_types.add(rtype)

        unique_subs = set(all_subdomains)
        if len(unique_subs) < 3:
            continue

        avg_len = _avg_length(list(unique_subs))
        max_len = max((len(s) for s in unique_subs), default=0)
        has_enc = _has_encoded_labels(list(unique_subs))

        signals = 0
        if avg_len > 20:
            signals += 2
        elif avg_len > 10:
            signals += 1
        if has_enc:
            signals += 2
        if len(unique_subs) > 10:
            signals += 1
        if max_len > 50:
            signals += 1
        if "TXT" in record_types:
            signals += 1

        if signals < 2:
            continue

        if signals >= 4:
            confidence = "high"
        elif signals >= 3:
            confidence = "medium"
        else:
            confidence = "low"

        desc_parts = [f"{len(unique_subs)} unique subdomains for {domain}"]
        if has_enc:
            desc_parts.append("encoded labels detected")
        if avg_len > 20:
            desc_parts.append(f"avg label length {avg_len}")
        if "TXT" in record_types:
            desc_parts.append("TXT records used")

        detections.append(DNSTunnelDetection(
            agent_id=agent,
            domain=domain,
            query_count=len(evts),
            unique_subdomains=len(unique_subs),
            avg_subdomain_length=avg_len,
            max_subdomain_length=max_len,
            has_encoding=has_enc,
            record_types=sorted(record_types),
            confidence=confidence,
            description="; ".join(desc_parts),
        ))


def _detect_high_volume(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[HighVolumeQuery],
) -> None:
    domain_ts: dict[str, list[str]] = defaultdict(list)
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_dns_tool(tool):
            continue
        query = ev.get("resource", ev.get("query", ev.get("domain", "")))
        ts = ev.get("timestamp", "")
        if query and ts:
            domain = _extract_domain(query)
            domain_ts[domain].append(ts)

    for domain, timestamps in domain_ts.items():
        if len(timestamps) < 5:
            continue
        parsed = [_parse_ts(t) for t in timestamps]
        parsed = [p for p in parsed if p is not None]
        if len(parsed) < 2:
            continue
        parsed.sort()
        span = (parsed[-1] - parsed[0]).total_seconds()
        if span <= 0:
            continue
        qpm = (len(parsed) / span) * 60

        if qpm < 1.0:
            continue

        if qpm >= 10:
            confidence = "high"
        elif qpm >= 3:
            confidence = "medium"
        else:
            confidence = "low"

        sorted_ts = sorted(timestamps)
        detections.append(HighVolumeQuery(
            agent_id=agent,
            domain=domain,
            query_count=len(timestamps),
            time_span_seconds=round(span, 2),
            queries_per_minute=round(qpm, 2),
            first_seen=sorted_ts[0],
            last_seen=sorted_ts[-1],
            confidence=confidence,
        ))


def _detect_suspicious(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[SuspiciousDNS],
) -> None:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_dns_tool(tool):
            continue
        query = ev.get("resource", ev.get("query", ev.get("domain", "")))
        ts = ev.get("timestamp", "")
        if not query:
            continue

        reasons: list[str] = []
        subs = _extract_subdomains(query)
        if any(len(s) > 50 for s in subs):
            reasons.append("extremely long subdomain label")
        if _is_suspicious_tld(query):
            reasons.append("suspicious dynamic DNS TLD")
        rtype = ev.get("record_type", ev.get("type", "")).upper()
        if rtype in ("TXT", "NULL", "CNAME") and subs and _has_encoded_labels(subs):
            reasons.append(f"encoded payload in {rtype} query")

        if reasons:
            detections.append(SuspiciousDNS(
                agent_id=agent,
                query=query,
                reason="; ".join(reasons),
                timestamp=ts,
                tool=tool,
            ))


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
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


def format_text(report: DNSTunnelReport) -> str:
    lines: list[str] = []
    lines.append("DNS Tunneling Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Tunnel detections:    {s.total_tunnel_detections}")
    lines.append(f"  High-volume queries:  {s.total_high_volume}")
    lines.append(f"  Suspicious queries:   {s.total_suspicious}")
    lines.append(f"  Agents involved:      {s.agents_involved}")
    lines.append(f"  Domains flagged:      {s.domains_flagged}")
    lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    if report.tunnel_detections:
        lines.append("  Tunnel Detections:")
        lines.append("  " + "-" * 58)
        for d in report.tunnel_detections:
            lines.append(f"    [{d.confidence.upper()}] {d.agent_id} -> {d.domain}")
            lines.append(f"      Queries: {d.query_count}, Unique subdomains: {d.unique_subdomains}")
            lines.append(f"      Avg label len: {d.avg_subdomain_length}, Max: {d.max_subdomain_length}")
            enc = "YES" if d.has_encoding else "no"
            lines.append(f"      Encoding: {enc}, Record types: {', '.join(d.record_types) or 'none'}")
            lines.append(f"      {d.description}")
        lines.append("")

    if report.high_volume_queries:
        lines.append("  High-Volume DNS Queries:")
        lines.append("  " + "-" * 58)
        for hv in report.high_volume_queries:
            lines.append(f"    [{hv.confidence.upper()}] {hv.agent_id} -> {hv.domain}")
            lines.append(f"      {hv.query_count} queries in {hv.time_span_seconds}s ({hv.queries_per_minute} qpm)")
            lines.append(f"      Period: {hv.first_seen} to {hv.last_seen}")
        lines.append("")

    if report.suspicious_queries:
        lines.append("  Suspicious DNS Queries:")
        lines.append("  " + "-" * 58)
        for sq in report.suspicious_queries:
            lines.append(f"    {sq.agent_id}: {sq.query}")
            lines.append(f"      Reason: {sq.reason}")
            lines.append(f"      Tool: {sq.tool}, Time: {sq.timestamp}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: DNSTunnelReport) -> str:
    data = {
        "tunnel_detections": [asdict(d) for d in report.tunnel_detections],
        "high_volume_queries": [asdict(hv) for hv in report.high_volume_queries],
        "suspicious_queries": [asdict(sq) for sq in report.suspicious_queries],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
