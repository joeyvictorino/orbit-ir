"""Cascading impact chain analysis for agent incidents.

Traces how one agent's action cascades through a multi-agent system—
when agent A modifies a resource that agent B reads, then B acts on
agent C's resource, the module links those into a chain and scores
the amplification at each hop.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


WRITE_ACTIONS = {
    "write_file", "create_file", "modify_file", "delete_file",
    "http_post", "http_put", "send_email", "upload_file",
    "api_call", "send_message", "modify_role", "grant_permission",
    "create_credential", "modify_policy", "update_iam",
    "write_external", "push_data", "set_config",
}

READ_ACTIONS = {
    "read_file", "list_directory", "search_files", "glob_files",
    "read_database", "query_db", "http_get", "api_call",
    "read_config", "get_credentials", "read_secret",
}

AMPLIFICATION_MARKERS = {
    "broadcast", "fan_out", "replicate", "forward", "relay",
    "distribute", "propagate", "multicast", "spawn",
}


@dataclass
class ImpactChainLink:
    agent_id: str
    timestamp: str
    action: str
    resource: str
    effect: str
    bytes_estimate: int
    link_type: str  # "origin", "relay", "terminal"


@dataclass
class ImpactChain:
    chain_id: str
    links: list[ImpactChainLink] = field(default_factory=list)
    depth: int = 0
    agents_involved: list[str] = field(default_factory=list)
    resources_touched: list[str] = field(default_factory=list)
    total_bytes: int = 0
    severity: str = "low"
    description: str = ""


@dataclass
class AmplificationPoint:
    agent_id: str
    timestamp: str
    action: str
    resource: str
    fan_out: int
    downstream_agents: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class BlastRadius:
    agents_affected: int
    resources_affected: int
    max_chain_depth: int
    total_bytes_at_risk: int


@dataclass
class ImpactChainSummary:
    total_chains: int
    max_depth: int
    by_severity: dict[str, int] = field(default_factory=dict)
    amplification_points: int = 0
    agents_in_chains: int = 0
    resources_in_chains: int = 0


@dataclass
class ImpactChainReport:
    chains: list[ImpactChain]
    amplification_points: list[AmplificationPoint]
    blast_radius: BlastRadius
    summary: ImpactChainSummary


def _is_write(tool: str) -> bool:
    lower = tool.lower()
    return lower in WRITE_ACTIONS or any(k in lower for k in {"write", "create", "modify", "delete", "send", "upload", "push", "set"})


def _is_read(tool: str) -> bool:
    lower = tool.lower()
    return lower in READ_ACTIONS or any(k in lower for k in {"read", "get", "list", "query", "fetch", "search"})


def _is_amplification(tool: str, effect: str) -> bool:
    lower = (tool + " " + effect).lower()
    return any(m in lower for m in AMPLIFICATION_MARKERS)


def _estimate_bytes(ev: dict[str, Any]) -> int:
    size = ev.get("bytes", 0) or ev.get("payload_size", 0) or ev.get("size", 0)
    if isinstance(size, (int, float)):
        return int(size)
    return 0


def _normalize_resource(resource: str) -> str:
    return resource.strip().lower().rstrip("/")


def analyze_impact_chains(events: list[dict[str, Any]]) -> ImpactChainReport:
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

    resource_writers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    resource_readers: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in sorted_events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        resource = ev.get("resource", "")
        if not resource:
            continue
        norm = _normalize_resource(resource)
        if _is_write(tool):
            resource_writers[norm].append(ev)
        if _is_read(tool):
            resource_readers[norm].append(ev)

    chains: list[ImpactChain] = []
    chain_counter = 0

    for resource_key, writers in sorted(resource_writers.items()):
        readers = resource_readers.get(resource_key, [])
        for writer in writers:
            w_agent = writer.get("agent_id", "")
            w_ts = writer.get("timestamp", "")
            if not w_agent:
                continue

            downstream_reads = [
                r for r in readers
                if r.get("agent_id", "") != w_agent
                and r.get("timestamp", "") >= w_ts
            ]
            if not downstream_reads:
                continue

            chain_counter += 1
            links: list[ImpactChainLink] = []
            tool = writer.get("tool", writer.get("claimed_tool", ""))
            links.append(ImpactChainLink(
                agent_id=w_agent,
                timestamp=w_ts,
                action=tool,
                resource=writer.get("resource", ""),
                effect=writer.get("effect", ""),
                bytes_estimate=_estimate_bytes(writer),
                link_type="origin",
            ))

            seen_agents = {w_agent}
            chain_resources = {resource_key}

            for reader in downstream_reads:
                r_agent = reader.get("agent_id", "")
                r_tool = reader.get("tool", reader.get("claimed_tool", ""))
                links.append(ImpactChainLink(
                    agent_id=r_agent,
                    timestamp=reader.get("timestamp", ""),
                    action=r_tool,
                    resource=reader.get("resource", ""),
                    effect=reader.get("effect", ""),
                    bytes_estimate=_estimate_bytes(reader),
                    link_type="relay" if r_agent in seen_agents else "terminal",
                ))
                seen_agents.add(r_agent)
                chain_resources.add(_normalize_resource(reader.get("resource", "")))

                subsequent_writes = [
                    w for w in sorted_events
                    if w.get("agent_id", "") == r_agent
                    and w.get("timestamp", "") >= reader.get("timestamp", "")
                    and _is_write(w.get("tool", w.get("claimed_tool", "")))
                    and w.get("resource", "") and _normalize_resource(w.get("resource", "")) != resource_key
                ]
                for sw in subsequent_writes[:2]:
                    sw_tool = sw.get("tool", sw.get("claimed_tool", ""))
                    links.append(ImpactChainLink(
                        agent_id=r_agent,
                        timestamp=sw.get("timestamp", ""),
                        action=sw_tool,
                        resource=sw.get("resource", ""),
                        effect=sw.get("effect", ""),
                        bytes_estimate=_estimate_bytes(sw),
                        link_type="relay",
                    ))
                    chain_resources.add(_normalize_resource(sw.get("resource", "")))

            agents_list = sorted(seen_agents)
            resources_list = sorted(chain_resources)
            total_bytes = sum(l.bytes_estimate for l in links)
            depth = len({l.agent_id for l in links})
            severity = _chain_severity(links, depth)

            chains.append(ImpactChain(
                chain_id=f"IC-{chain_counter:03d}",
                links=links,
                depth=depth,
                agents_involved=agents_list,
                resources_touched=resources_list,
                total_bytes=total_bytes,
                severity=severity,
                description=_chain_description(w_agent, agents_list, resources_list, depth),
            ))

    chains.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c.severity, 4))

    amp_points = _find_amplification(sorted_events, resource_writers)

    all_agents = set()
    all_resources = set()
    max_depth = 0
    total_bytes = 0
    for c in chains:
        all_agents.update(c.agents_involved)
        all_resources.update(c.resources_touched)
        max_depth = max(max_depth, c.depth)
        total_bytes += c.total_bytes

    sev_counts: dict[str, int] = defaultdict(int)
    for c in chains:
        sev_counts[c.severity] += 1

    return ImpactChainReport(
        chains=chains,
        amplification_points=amp_points,
        blast_radius=BlastRadius(
            agents_affected=len(all_agents),
            resources_affected=len(all_resources),
            max_chain_depth=max_depth,
            total_bytes_at_risk=total_bytes,
        ),
        summary=ImpactChainSummary(
            total_chains=len(chains),
            max_depth=max_depth,
            by_severity=dict(sev_counts),
            amplification_points=len(amp_points),
            agents_in_chains=len(all_agents),
            resources_in_chains=len(all_resources),
        ),
    )


def _chain_severity(links: list[ImpactChainLink], depth: int) -> str:
    has_large_payload = any(l.bytes_estimate >= 100000 for l in links)
    has_sensitive = any(
        any(kw in l.resource.lower() for kw in ("secret", "credential", "key", "token", "password", "admin"))
        for l in links
    )
    if depth >= 4 and has_sensitive:
        return "critical"
    if depth >= 4 or (depth >= 3 and has_sensitive):
        return "high"
    if depth >= 3 or has_large_payload or has_sensitive:
        return "medium"
    return "low"


def _chain_description(origin: str, agents: list[str], resources: list[str], depth: int) -> str:
    others = [a for a in agents if a != origin]
    parts = [f"Agent '{origin}' initiated a cascading chain affecting {len(others)} other agent(s)"]
    parts.append(f"touching {len(resources)} resource(s) across {depth} hop(s)")
    return ", ".join(parts)


def _find_amplification(
    events: list[dict[str, Any]],
    resource_writers: dict[str, list[dict[str, Any]]],
) -> list[AmplificationPoint]:
    amp_points: list[AmplificationPoint] = []

    agent_write_counts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ""))
        if _is_write(tool) and ev.get("agent_id"):
            agent_write_counts[ev["agent_id"]].append(ev)

    for agent, writes in sorted(agent_write_counts.items()):
        if len(writes) < 3:
            continue
        targets = set()
        for w in writes:
            resource = w.get("resource", "")
            if resource:
                norm = _normalize_resource(resource)
                for ev_list in resource_writers.values():
                    pass
                targets.add(norm)

        downstream_agents = set()
        for w in writes:
            resource = w.get("resource", "")
            if not resource:
                continue
            norm = _normalize_resource(resource)
            for ev in events:
                if (ev.get("agent_id", "") != agent
                    and _normalize_resource(ev.get("resource", "")) == norm
                    and ev.get("timestamp", "") >= w.get("timestamp", "")):
                    downstream_agents.add(ev.get("agent_id", ""))

        if len(downstream_agents) >= 2 or len(writes) >= 5:
            tool = writes[0].get("tool", writes[0].get("claimed_tool", ""))
            effect = writes[0].get("effect", "")
            amp_points.append(AmplificationPoint(
                agent_id=agent,
                timestamp=writes[0].get("timestamp", ""),
                action=tool,
                resource=writes[0].get("resource", ""),
                fan_out=len(downstream_agents) if downstream_agents else len(writes),
                downstream_agents=sorted(downstream_agents),
                description=f"Agent '{agent}' wrote to {len(targets)} resources affecting {len(downstream_agents)} downstream agent(s)",
            ))

    return amp_points


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


def format_text(report: ImpactChainReport) -> str:
    lines: list[str] = []
    lines.append("Cascading Impact Chain Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total chains:           {s.total_chains}")
    lines.append(f"  Max chain depth:        {s.max_depth}")
    lines.append(f"  Agents in chains:       {s.agents_in_chains}")
    lines.append(f"  Resources in chains:    {s.resources_in_chains}")
    lines.append(f"  Amplification points:   {s.amplification_points}")
    lines.append("")

    if s.by_severity:
        lines.append("  By Severity:")
        for sev, count in sorted(s.by_severity.items()):
            lines.append(f"    {sev}: {count}")
        lines.append("")

    br = report.blast_radius
    lines.append("  Blast Radius:")
    lines.append(f"    Agents affected:      {br.agents_affected}")
    lines.append(f"    Resources affected:   {br.resources_affected}")
    lines.append(f"    Max chain depth:      {br.max_chain_depth}")
    lines.append(f"    Total bytes at risk:  {br.total_bytes_at_risk}")
    lines.append("")

    for c in report.chains:
        lines.append(f"  [{c.severity.upper()}] {c.chain_id}")
        lines.append(f"    {c.description}")
        lines.append(f"    Depth: {c.depth}, Agents: {', '.join(c.agents_involved)}")
        if c.resources_touched:
            lines.append(f"    Resources: {', '.join(c.resources_touched[:5])}")
            if len(c.resources_touched) > 5:
                lines.append(f"    ... and {len(c.resources_touched) - 5} more")
        lines.append(f"    Bytes: {c.total_bytes}")
        for link in c.links:
            lines.append(f"      [{link.link_type}] {link.timestamp}: {link.agent_id} -> {link.action} on {link.resource}")
        lines.append("")

    if report.amplification_points:
        lines.append("  Amplification Points:")
        lines.append("  " + "-" * 60)
        for ap in report.amplification_points:
            lines.append(f"    {ap.agent_id}: fan-out={ap.fan_out}")
            lines.append(f"      {ap.description}")
            if ap.downstream_agents:
                lines.append(f"      Downstream: {', '.join(ap.downstream_agents)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ImpactChainReport) -> str:
    data = {
        "chains": [
            {
                **{k: v for k, v in asdict(c).items() if k != "links"},
                "links": [asdict(l) for l in c.links],
            }
            for c in report.chains
        ],
        "amplification_points": [asdict(ap) for ap in report.amplification_points],
        "blast_radius": asdict(report.blast_radius),
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
