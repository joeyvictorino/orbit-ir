"""DNS tunneling detection for agent evidence.

Analyzes agent evidence for DNS tunneling patterns — agents using DNS
queries to exfiltrate data or establish covert communication channels.
Detects high-entropy subdomain queries, unusual query volumes, TXT
record abuse, and encoded payloads in DNS names.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


KNOWN_TUNNEL_DOMAINS = {
    "dnscat", "iodine", "dns2tcp", "dnsexfiltrator", "dnstunnel",
    "requestbin", "burpcollaborator", "interact.sh", "oastify",
}

TXT_ABUSE_THRESHOLD = 5
QUERY_VOLUME_THRESHOLD = 50
LONG_SUBDOMAIN_THRESHOLD = 63
HIGH_ENTROPY_THRESHOLD = 3.5
BEACON_MIN_COUNT = 4
BEACON_JITTER_RATIO = 0.25


@dataclass
class DnsTunnelFinding:
    agent_id: str
    pattern: str
    domain: str
    timestamp: str
    confidence: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class DnsTunnelSummary:
    total_findings: int
    high_entropy: int
    txt_abuse: int
    volume_spike: int
    long_subdomain: int
    known_tunnel: int
    periodic_beacon: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class DnsTunnelReport:
    findings: list[DnsTunnelFinding]
    summary: DnsTunnelSummary
    agents_involved: list[str]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_subdomain(domain: str) -> str:
    parts = domain.strip(".").split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def _is_known_tunnel_domain(domain: str) -> bool:
    lower = domain.lower()
    return any(k in lower for k in KNOWN_TUNNEL_DOMAINS)


def analyze_dns_tunneling(events: list[dict[str, Any]]) -> DnsTunnelReport:
    agent_dns: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        lower_tool = str(tool).lower()
        lower_res = str(resource).lower()
        if any(k in lower_tool for k in ("dns", "resolve", "lookup", "nslookup", "dig")) or \
           any(k in lower_res for k in ("dns", ".arpa", "query")):
            agent_dns[agent].append(ev)

    findings: list[DnsTunnelFinding] = []

    for agent, dns_events in sorted(agent_dns.items()):
        dns_events.sort(key=lambda e: e.get("timestamp", ""))
        _detect_high_entropy(agent, dns_events, findings)
        _detect_txt_abuse(agent, dns_events, findings)
        _detect_volume_spike(agent, dns_events, findings)
        _detect_long_subdomain(agent, dns_events, findings)
        _detect_known_tunnel(agent, dns_events, findings)
        _detect_periodic_beacon(agent, dns_events, findings)

    all_agents = sorted({f.agent_id for f in findings})
    conf: dict[str, int] = defaultdict(int)
    pattern_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        conf[f.confidence] += 1
        pattern_counts[f.pattern] += 1

    return DnsTunnelReport(
        findings=findings,
        summary=DnsTunnelSummary(
            total_findings=len(findings),
            high_entropy=pattern_counts.get("dns_high_entropy_subdomain", 0),
            txt_abuse=pattern_counts.get("dns_txt_record_abuse", 0),
            volume_spike=pattern_counts.get("dns_query_volume_spike", 0),
            long_subdomain=pattern_counts.get("dns_long_subdomain", 0),
            known_tunnel=pattern_counts.get("dns_known_tunnel_domain", 0),
            periodic_beacon=pattern_counts.get("dns_periodic_beacon", 0),
            agents_involved=len(all_agents),
            by_confidence=dict(conf),
        ),
        agents_involved=all_agents,
    )


def _detect_high_entropy(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    for ev in events:
        domain = ev.get("resource", ev.get("target", ""))
        subdomain = _extract_subdomain(domain)
        if not subdomain:
            continue
        entropy = _shannon_entropy(subdomain.replace(".", ""))
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            findings.append(DnsTunnelFinding(
                agent_id=agent,
                pattern="dns_high_entropy_subdomain",
                domain=domain,
                timestamp=ev.get("timestamp", ""),
                confidence="high" if entropy >= 4.0 else "medium",
                description=f"Agent '{agent}' queried domain with high-entropy subdomain (entropy={entropy:.2f}): {domain}",
                evidence={"entropy": round(entropy, 2), "subdomain": subdomain},
            ))


def _detect_txt_abuse(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    txt_queries = [
        ev for ev in events
        if "txt" in str(ev.get("query_type", ev.get("record_type", ""))).lower()
    ]
    if len(txt_queries) >= TXT_ABUSE_THRESHOLD:
        ts = txt_queries[-1].get("timestamp", "")
        domains = sorted(set(ev.get("resource", ev.get("target", "")) for ev in txt_queries))
        findings.append(DnsTunnelFinding(
            agent_id=agent,
            pattern="dns_txt_record_abuse",
            domain=domains[0] if domains else "",
            timestamp=ts,
            confidence="high" if len(txt_queries) >= 10 else "medium",
            description=f"Agent '{agent}' made {len(txt_queries)} TXT record queries, suggesting data channel",
            evidence={"txt_count": len(txt_queries), "domains": domains[:5]},
        ))


def _detect_volume_spike(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    if len(events) >= QUERY_VOLUME_THRESHOLD:
        ts = events[-1].get("timestamp", "")
        findings.append(DnsTunnelFinding(
            agent_id=agent,
            pattern="dns_query_volume_spike",
            domain="multiple",
            timestamp=ts,
            confidence="high" if len(events) >= 100 else "medium",
            description=f"Agent '{agent}' made {len(events)} DNS queries, abnormally high volume",
            evidence={"query_count": len(events)},
        ))


def _detect_long_subdomain(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    for ev in events:
        domain = ev.get("resource", ev.get("target", ""))
        subdomain = _extract_subdomain(domain)
        if not subdomain:
            continue
        labels = subdomain.split(".")
        max_label = max((len(l) for l in labels), default=0)
        if max_label >= LONG_SUBDOMAIN_THRESHOLD or len(labels) >= 5:
            findings.append(DnsTunnelFinding(
                agent_id=agent,
                pattern="dns_long_subdomain",
                domain=domain,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' queried domain with unusually long subdomain labels: {domain}",
                evidence={"max_label_length": max_label, "label_depth": len(labels)},
            ))


def _detect_known_tunnel(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    for ev in events:
        domain = ev.get("resource", ev.get("target", ""))
        if _is_known_tunnel_domain(domain):
            findings.append(DnsTunnelFinding(
                agent_id=agent,
                pattern="dns_known_tunnel_domain",
                domain=domain,
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' queried known DNS tunneling service: {domain}",
                evidence={"domain": domain},
            ))


def _detect_periodic_beacon(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[DnsTunnelFinding],
) -> None:
    timestamps = []
    for ev in events:
        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    if len(timestamps) < BEACON_MIN_COUNT:
        return

    timestamps.sort()
    intervals: list[float] = []
    for i in range(1, len(timestamps)):
        try:
            t1 = timestamps[i - 1]
            t2 = timestamps[i]
            diff = _ts_diff_seconds(t1, t2)
            if diff is not None and diff > 0:
                intervals.append(diff)
        except (ValueError, IndexError):
            continue

    if len(intervals) < 3:
        return

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval <= 0:
        return
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    cv = std_dev / mean_interval

    if cv <= BEACON_JITTER_RATIO:
        findings.append(DnsTunnelFinding(
            agent_id=agent,
            pattern="dns_periodic_beacon",
            domain="multiple",
            timestamp=timestamps[-1],
            confidence="high" if cv <= 0.1 else "medium",
            description=f"Agent '{agent}' DNS queries show periodic beaconing (interval ~{mean_interval:.0f}s, CV={cv:.2f})",
            evidence={"mean_interval_s": round(mean_interval, 1), "cv": round(cv, 3), "sample_count": len(intervals)},
        ))


def _ts_diff_seconds(t1: str, t2: str) -> float | None:
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            d1 = datetime.strptime(t1, fmt)
            d2 = datetime.strptime(t2, fmt)
            return (d2 - d1).total_seconds()
        except ValueError:
            continue
    return None


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


def format_text(report: DnsTunnelReport) -> str:
    lines: list[str] = []
    lines.append("DNS Tunneling Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total findings:         {s.total_findings}")
    lines.append(f"  High-entropy subdomains:{s.high_entropy}")
    lines.append(f"  TXT record abuse:       {s.txt_abuse}")
    lines.append(f"  Volume spikes:          {s.volume_spike}")
    lines.append(f"  Long subdomains:        {s.long_subdomain}")
    lines.append(f"  Known tunnel domains:   {s.known_tunnel}")
    lines.append(f"  Periodic beacons:       {s.periodic_beacon}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if report.findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 58)
        for f in report.findings:
            lines.append(f"    [{f.confidence.upper()}] {f.pattern}: {f.agent_id}")
            lines.append(f"      {f.description}")
            lines.append(f"      Domain: {f.domain}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: DnsTunnelReport) -> str:
    data = {
        "findings": [asdict(f) for f in report.findings],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
