"""Network scanning pattern detection for agent evidence.

Analyzes agent event sequences to detect network scanning activities—
port sweeps, service discovery, host enumeration, and systematic
network mapping.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


SCAN_TOOLS = {
    "port_scan", "nmap", "scan_port", "scan_host", "enumerate",
    "discover", "probe", "sweep", "fingerprint_service", "portscan",
    "host_scan", "service_scan", "net_scan", "network_scan",
}

NETWORK_RECON_TOOLS = {
    "dns_lookup", "reverse_dns", "whois", "traceroute", "ping",
    "arp_scan", "netstat", "ss", "ip_route", "ifconfig",
    "resolve_host", "dig", "nslookup", "host_lookup",
}

SCAN_INDICATORS = {
    "port", "host", "subnet", "cidr", "range", "scan", "sweep",
    "enumerate", "discover", "probe", "fingerprint", "banner",
}


@dataclass
class PortSweep:
    agent_id: str
    target_host: str
    ports_scanned: list[int]
    port_count: int
    first_seen: str
    last_seen: str
    scan_rate: float
    confidence: str


@dataclass
class HostEnumeration:
    agent_id: str
    network: str
    hosts_discovered: list[str]
    host_count: int
    first_seen: str
    last_seen: str
    method: str
    confidence: str


@dataclass
class ServiceDiscovery:
    agent_id: str
    target: str
    services_found: list[dict[str, Any]]
    service_count: int
    timestamp: str
    confidence: str


@dataclass
class NetworkScanSummary:
    total_port_sweeps: int
    total_host_enumerations: int
    total_service_discoveries: int
    agents_scanning: int
    unique_targets: int
    total_ports_scanned: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class NetworkScanReport:
    port_sweeps: list[PortSweep]
    host_enumerations: list[HostEnumeration]
    service_discoveries: list[ServiceDiscovery]
    summary: NetworkScanSummary
    agents_involved: list[str]


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_scan_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in SCAN_TOOLS or any(k in lower for k in {"scan", "sweep", "enumerate", "probe"})


def _is_recon_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in NETWORK_RECON_TOOLS or any(k in lower for k in {"dns", "lookup", "resolve", "trace", "ping"})


def _has_scan_indicator(event: dict[str, Any]) -> bool:
    for val in [event.get("tool", ""), event.get("resource", ""), event.get("effect", "")]:
        lower = str(val).lower()
        if any(k in lower for k in SCAN_INDICATORS):
            return True
    return False


def _extract_port(resource: str) -> int | None:
    parts = resource.split(":")
    if len(parts) >= 2:
        try:
            return int(parts[-1])
        except ValueError:
            pass
    for part in resource.split():
        try:
            p = int(part)
            if 1 <= p <= 65535:
                return p
        except ValueError:
            continue
    return None


def _extract_host(resource: str) -> str:
    parts = resource.split(":")
    if len(parts) >= 2:
        return parts[0]
    parts = resource.split("/")
    if parts:
        return parts[0]
    return resource


def analyze_network_scans(events: list[dict[str, Any]]) -> NetworkScanReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    port_sweeps: list[PortSweep] = []
    host_enums: list[HostEnumeration] = []
    service_discs: list[ServiceDiscovery] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        _detect_port_sweeps(agent, evts_sorted, port_sweeps)
        _detect_host_enumeration(agent, evts_sorted, host_enums)
        _detect_service_discovery(agent, evts_sorted, service_discs)

    all_agents = set()
    conf_counts: dict[str, int] = defaultdict(int)
    all_targets = set()
    total_ports = 0

    for ps in port_sweeps:
        all_agents.add(ps.agent_id)
        conf_counts[ps.confidence] += 1
        all_targets.add(ps.target_host)
        total_ports += ps.port_count
    for he in host_enums:
        all_agents.add(he.agent_id)
        conf_counts[he.confidence] += 1
        all_targets.add(he.network)
    for sd in service_discs:
        all_agents.add(sd.agent_id)
        conf_counts[sd.confidence] += 1
        all_targets.add(sd.target)

    return NetworkScanReport(
        port_sweeps=port_sweeps,
        host_enumerations=host_enums,
        service_discoveries=service_discs,
        summary=NetworkScanSummary(
            total_port_sweeps=len(port_sweeps),
            total_host_enumerations=len(host_enums),
            total_service_discoveries=len(service_discs),
            agents_scanning=len(all_agents),
            unique_targets=len(all_targets),
            total_ports_scanned=total_ports,
            by_confidence=dict(conf_counts),
        ),
        agents_involved=sorted(all_agents),
    )


def _detect_port_sweeps(
    agent: str,
    events: list[dict[str, Any]],
    sweeps: list[PortSweep],
) -> None:
    host_ports: dict[str, list[tuple[int, str]]] = defaultdict(list)

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        ts = ev.get("timestamp", "")

        if not (_is_scan_tool(tool) or _has_scan_indicator(ev)):
            continue

        port = _extract_port(resource)
        host = _extract_host(resource)
        if port and host:
            host_ports[host].append((port, ts))

    for host, port_ts_list in host_ports.items():
        if len(port_ts_list) < 3:
            continue

        ports = sorted(set(p for p, _ in port_ts_list))
        timestamps = [t for _, t in port_ts_list if t]

        first = min(timestamps) if timestamps else ""
        last = max(timestamps) if timestamps else ""

        scan_rate = 0.0
        if first and last:
            dt_first = _parse_ts(first)
            dt_last = _parse_ts(last)
            if dt_first and dt_last:
                duration = (dt_last - dt_first).total_seconds()
                if duration > 0:
                    scan_rate = round(len(ports) / duration, 2)

        if len(ports) >= 10:
            confidence = "high"
        elif len(ports) >= 5:
            confidence = "medium"
        else:
            confidence = "low"

        sweeps.append(PortSweep(
            agent_id=agent,
            target_host=host,
            ports_scanned=ports,
            port_count=len(ports),
            first_seen=first,
            last_seen=last,
            scan_rate=scan_rate,
            confidence=confidence,
        ))


def _detect_host_enumeration(
    agent: str,
    events: list[dict[str, Any]],
    enums: list[HostEnumeration],
) -> None:
    network_hosts: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        ts = ev.get("timestamp", "")

        if not (_is_scan_tool(tool) or _is_recon_tool(tool)):
            continue

        host = _extract_host(resource)
        if not host:
            continue

        parts = host.split(".")
        is_ip = len(parts) == 4 and all(p.isdigit() for p in parts)
        if is_ip:
            network = ".".join(parts[:3]) + ".0/24"
        elif len(parts) >= 2:
            network = ".".join(parts[-2:])
        else:
            network = host

        method = "scan" if _is_scan_tool(tool) else "recon"
        network_hosts[network].append((host, ts, method))

    for network, host_data in network_hosts.items():
        hosts = sorted(set(h for h, _, _ in host_data))
        if len(hosts) < 3:
            continue

        timestamps = [t for _, t, _ in host_data if t]
        first = min(timestamps) if timestamps else ""
        last = max(timestamps) if timestamps else ""
        methods = set(m for _, _, m in host_data)
        method = "mixed" if len(methods) > 1 else methods.pop()

        if len(hosts) >= 10:
            confidence = "high"
        elif len(hosts) >= 5:
            confidence = "medium"
        else:
            confidence = "low"

        enums.append(HostEnumeration(
            agent_id=agent,
            network=network,
            hosts_discovered=hosts,
            host_count=len(hosts),
            first_seen=first,
            last_seen=last,
            method=method,
            confidence=confidence,
        ))


def _detect_service_discovery(
    agent: str,
    events: list[dict[str, Any]],
    discoveries: list[ServiceDiscovery],
) -> None:
    target_services: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", ev.get("target", ""))
        effect = ev.get("effect", "")
        ts = ev.get("timestamp", "")

        if not resource:
            continue

        is_discovery = (
            _is_scan_tool(tool)
            and any(k in effect.lower() for k in {"discover", "found", "open", "service", "banner"})
        )
        if not is_discovery:
            is_discovery = "fingerprint" in tool.lower() or "banner" in effect.lower()

        if is_discovery:
            host = _extract_host(resource)
            port = _extract_port(resource)
            target_services[host].append({
                "port": port,
                "service": effect,
                "tool": tool,
                "timestamp": ts,
            })

    for target, services in target_services.items():
        if len(services) < 2:
            continue

        if len(services) >= 5:
            confidence = "high"
        elif len(services) >= 3:
            confidence = "medium"
        else:
            confidence = "low"

        latest_ts = max((s["timestamp"] for s in services if s["timestamp"]), default="")

        discoveries.append(ServiceDiscovery(
            agent_id=agent,
            target=target,
            services_found=services,
            service_count=len(services),
            timestamp=latest_ts,
            confidence=confidence,
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


def format_text(report: NetworkScanReport) -> str:
    lines: list[str] = []
    lines.append("Network Scanning Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Port sweeps:            {s.total_port_sweeps}")
    lines.append(f"  Host enumerations:      {s.total_host_enumerations}")
    lines.append(f"  Service discoveries:    {s.total_service_discoveries}")
    lines.append(f"  Agents scanning:        {s.agents_scanning}")
    lines.append(f"  Unique targets:         {s.unique_targets}")
    lines.append(f"  Total ports scanned:    {s.total_ports_scanned}")
    lines.append("")

    if report.port_sweeps:
        lines.append("  Port Sweeps:")
        lines.append("  " + "-" * 58)
        for ps in report.port_sweeps:
            lines.append(f"    [{ps.confidence.upper()}] {ps.agent_id} -> {ps.target_host}")
            lines.append(f"      Ports: {ps.port_count} scanned, rate: {ps.scan_rate}/s")
            lines.append(f"      Period: {ps.first_seen} to {ps.last_seen}")
        lines.append("")

    if report.host_enumerations:
        lines.append("  Host Enumerations:")
        lines.append("  " + "-" * 58)
        for he in report.host_enumerations:
            lines.append(f"    [{he.confidence.upper()}] {he.agent_id} -> {he.network}")
            lines.append(f"      Hosts: {he.host_count} discovered via {he.method}")
        lines.append("")

    if report.service_discoveries:
        lines.append("  Service Discoveries:")
        lines.append("  " + "-" * 58)
        for sd in report.service_discoveries:
            lines.append(f"    [{sd.confidence.upper()}] {sd.agent_id} -> {sd.target}")
            lines.append(f"      Services: {sd.service_count} found")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: NetworkScanReport) -> str:
    data = {
        "port_sweeps": [asdict(ps) for ps in report.port_sweeps],
        "host_enumerations": [asdict(he) for he in report.host_enumerations],
        "service_discoveries": [asdict(sd) for sd in report.service_discoveries],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
