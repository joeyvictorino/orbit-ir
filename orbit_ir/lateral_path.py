"""Lateral movement path reconstruction for agent evidence.

Analyzes agent event sequences to reconstruct lateral movement paths—
agent-to-agent communication, credential forwarding, pivoting through
intermediate hosts, and multi-hop attack chains. Maps detections to
MITRE ATT&CK Lateral Movement techniques.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MITRE_TECHNIQUES = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1021.006": "Windows Remote Management",
    "T1072": "Software Deployment Tools",
    "T1080": "Taint Shared Content",
    "T1210": "Exploitation of Remote Services",
    "T1534": "Internal Spearphishing",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Application Access Token",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1563": "Remote Service Session Hijacking",
    "T1570": "Lateral Tool Transfer",
}

REMOTE_ACCESS_TOOLS = {
    "ssh", "ssh_connect", "remote_shell", "rdp_connect", "winrm",
    "psexec", "wmic", "invoke_command", "remote_exec", "telnet",
    "rsh", "rlogin", "powershell_remote", "enter_pssession",
}

CREDENTIAL_FORWARD_TOOLS = {
    "pass_hash", "pass_ticket", "inject_token", "forward_credential",
    "use_token", "impersonate", "delegate_credential", "relay_auth",
    "ticket_inject", "kerberoast",
}

FILE_TRANSFER_TOOLS = {
    "scp", "sftp", "copy_file", "transfer_file", "upload_tool",
    "deploy_payload", "push_binary", "share_mount", "smb_copy",
    "write_remote", "send_file", "wget_remote", "curl_download",
}

PIVOT_TOOLS = {
    "pivot", "tunnel", "port_forward", "proxy", "socks_proxy",
    "reverse_tunnel", "ssh_tunnel", "chisel", "ligolo", "socat",
    "netcat_relay", "create_tunnel",
}

AGENT_COMM_TOOLS = {
    "send_message", "delegate_task", "invoke_agent", "call_agent",
    "agent_request", "dispatch", "forward_request", "relay_command",
    "coordinate", "handoff",
}

REMOTE_ACCESS_RE = re.compile(
    r"(ssh\s|rdp\s|psexec|wmic\s|winrm|remote.?exec|remote.?shell|"
    r"invoke.?command|enter.?pssession|telnet\s|rlogin)",
    re.IGNORECASE,
)

PIVOT_RE = re.compile(
    r"(pivot|tunnel|port.?forward|socks.?proxy|reverse.?tunnel|"
    r"chisel|ligolo|socat|netcat.*relay)",
    re.IGNORECASE,
)


@dataclass
class LateralHop:
    hop_id: str
    source_agent: str
    target_agent: str
    method: str
    technique_id: str
    technique_name: str
    tool_used: str
    resource: str
    timestamp: str
    confidence: str


@dataclass
class LateralPath:
    path_id: str
    hops: list[LateralHop]
    total_hops: int
    start_agent: str
    end_agent: str
    techniques_used: list[str]
    risk_level: str


@dataclass
class LateralSummary:
    total_hops: int
    total_paths: int
    unique_techniques: int
    agents_involved: int
    by_method: dict[str, int]
    by_risk: dict[str, int]
    longest_path: int
    avg_path_length: float


@dataclass
class LateralReport:
    hops: list[LateralHop]
    paths: list[LateralPath]
    summary: LateralSummary
    agents_involved: list[str]


def _get_tool(ev: dict[str, Any]) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))


def _classify_method(tool: str, resource: str, effect: str) -> tuple[str, str, str] | None:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    lower_effect = effect.lower()
    combined = f"{lower_tool} {lower_resource} {lower_effect}"

    if lower_tool in REMOTE_ACCESS_TOOLS or REMOTE_ACCESS_RE.search(combined):
        if "ssh" in combined:
            return "remote-service", "T1021.004", "SSH"
        if "rdp" in combined:
            return "remote-service", "T1021.001", "Remote Desktop Protocol"
        if "smb" in combined or "psexec" in combined:
            return "remote-service", "T1021.002", "SMB/Windows Admin Shares"
        if "winrm" in combined:
            return "remote-service", "T1021.006", "Windows Remote Management"
        return "remote-service", "T1021", "Remote Services"

    if lower_tool in CREDENTIAL_FORWARD_TOOLS:
        if "hash" in combined:
            return "credential-forward", "T1550.002", "Pass the Hash"
        if "ticket" in combined:
            return "credential-forward", "T1550.003", "Pass the Ticket"
        if "token" in combined:
            return "credential-forward", "T1550.001", "Application Access Token"
        return "credential-forward", "T1550", "Use Alternate Authentication Material"

    if lower_tool in FILE_TRANSFER_TOOLS:
        return "tool-transfer", "T1570", "Lateral Tool Transfer"

    if lower_tool in PIVOT_TOOLS or PIVOT_RE.search(combined):
        return "pivot", "T1090", "Proxy"

    if lower_tool in AGENT_COMM_TOOLS:
        return "agent-delegation", "T1072", "Software Deployment Tools"

    if "exploit" in combined and ("remote" in combined or "service" in combined):
        return "exploitation", "T1210", "Exploitation of Remote Services"

    if "shared" in combined and ("content" in combined or "drive" in combined):
        return "taint-shared", "T1080", "Taint Shared Content"

    return None


def _infer_target(ev: dict[str, Any]) -> str:
    for key in ("target_agent", "target", "destination", "remote_host", "target_host"):
        val = ev.get(key, "")
        if val:
            return str(val)
    resource = ev.get("resource", "")
    if "@" in resource:
        parts = resource.split("@")
        if len(parts) == 2:
            return parts[1]
    return ""


def _assess_confidence(ev: dict[str, Any], method: str) -> str:
    tool = _get_tool(ev)
    if tool in REMOTE_ACCESS_TOOLS | CREDENTIAL_FORWARD_TOOLS:
        return "high"
    if tool in PIVOT_TOOLS | FILE_TRANSFER_TOOLS:
        return "medium"
    return "low"


def _assess_path_risk(hops: list[LateralHop]) -> str:
    if len(hops) >= 4:
        return "critical"
    if len(hops) >= 3:
        return "high"
    methods = {h.method for h in hops}
    if "credential-forward" in methods or "exploitation" in methods:
        return "high"
    if len(hops) >= 2:
        return "medium"
    return "low"


def analyze_lateral(events: list[dict[str, Any]]) -> LateralReport:
    hops: list[LateralHop] = []
    all_agents: set[str] = set()
    hop_counter = 0

    for ev in events:
        tool = _get_tool(ev)
        resource = ev.get("resource", "")
        effect = ev.get("effect", "")
        agent_id = ev.get("agent_id", ev.get("agent", "unknown"))

        classification = _classify_method(tool, resource, effect)
        if classification is None:
            continue

        method, technique_id, technique_name = classification
        target = _infer_target(ev)
        if not target:
            target = f"host-{hop_counter}"

        all_agents.add(agent_id)
        all_agents.add(target)
        hop_counter += 1

        hops.append(LateralHop(
            hop_id=f"hop-{hop_counter:04d}",
            source_agent=agent_id,
            target_agent=target,
            method=method,
            technique_id=technique_id,
            technique_name=technique_name,
            tool_used=tool,
            resource=resource,
            timestamp=ev.get("timestamp", ev.get("ts", "")),
            confidence=_assess_confidence(ev, method),
        ))

    paths = _reconstruct_paths(hops)

    method_counts: dict[str, int] = defaultdict(int)
    risk_counts: dict[str, int] = defaultdict(int)
    for h in hops:
        method_counts[h.method] += 1
    for p in paths:
        risk_counts[p.risk_level] += 1

    unique_techniques = len({h.technique_id for h in hops})
    longest = max((p.total_hops for p in paths), default=0)
    avg_len = sum(p.total_hops for p in paths) / len(paths) if paths else 0.0

    return LateralReport(
        hops=hops,
        paths=paths,
        summary=LateralSummary(
            total_hops=len(hops),
            total_paths=len(paths),
            unique_techniques=unique_techniques,
            agents_involved=len(all_agents),
            by_method=dict(method_counts),
            by_risk=dict(risk_counts),
            longest_path=longest,
            avg_path_length=round(avg_len, 1),
        ),
        agents_involved=sorted(all_agents),
    )


def _reconstruct_paths(hops: list[LateralHop]) -> list[LateralPath]:
    if not hops:
        return []

    adjacency: dict[str, list[LateralHop]] = defaultdict(list)
    for h in hops:
        adjacency[h.source_agent].append(h)

    sources = {h.source_agent for h in hops}
    targets = {h.target_agent for h in hops}
    start_agents = sources - targets
    if not start_agents:
        start_agents = {hops[0].source_agent}

    paths: list[LateralPath] = []
    path_counter = 0

    for start in sorted(start_agents):
        visited: set[str] = set()
        stack: list[tuple[str, list[LateralHop]]] = [(start, [])]

        while stack:
            current, chain = stack.pop()
            if current in visited:
                continue
            visited.add(current)

            next_hops = adjacency.get(current, [])
            if not next_hops and chain:
                path_counter += 1
                techniques = list(dict.fromkeys(h.technique_id for h in chain))
                paths.append(LateralPath(
                    path_id=f"path-{path_counter:04d}",
                    hops=list(chain),
                    total_hops=len(chain),
                    start_agent=chain[0].source_agent,
                    end_agent=chain[-1].target_agent,
                    techniques_used=techniques,
                    risk_level=_assess_path_risk(chain),
                ))
            else:
                for hop in next_hops:
                    if hop.target_agent not in visited:
                        stack.append((hop.target_agent, chain + [hop]))

        if not adjacency.get(start) and not any(p.start_agent == start for p in paths):
            continue

    if not paths and hops:
        path_counter += 1
        techniques = list(dict.fromkeys(h.technique_id for h in hops))
        paths.append(LateralPath(
            path_id=f"path-{path_counter:04d}",
            hops=list(hops),
            total_hops=len(hops),
            start_agent=hops[0].source_agent,
            end_agent=hops[-1].target_agent,
            techniques_used=techniques,
            risk_level=_assess_path_risk(hops),
        ))

    return paths


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


def format_text(report: LateralReport) -> str:
    lines: list[str] = []
    lines.append("Lateral Movement Path Reconstruction Report")
    lines.append("=" * 62)
    lines.append("")
    lines.append(f"  Total lateral hops:     {report.summary.total_hops}")
    lines.append(f"  Reconstructed paths:    {report.summary.total_paths}")
    lines.append(f"  Unique techniques:      {report.summary.unique_techniques}")
    lines.append(f"  Agents involved:        {report.summary.agents_involved}")
    lines.append(f"  Longest path:           {report.summary.longest_path} hops")
    lines.append(f"  Avg path length:        {report.summary.avg_path_length}")
    lines.append("")

    if report.summary.by_method:
        lines.append("  Methods:")
        for method, count in sorted(report.summary.by_method.items(), key=lambda x: -x[1]):
            lines.append(f"    {method:<25s} {count}")
        lines.append("")

    if report.summary.by_risk:
        lines.append("  Risk levels:")
        for risk, count in sorted(report.summary.by_risk.items()):
            lines.append(f"    {risk:<15s} {count}")
        lines.append("")

    if report.paths:
        lines.append("  Paths:")
        for p in report.paths:
            lines.append(f"    [{p.risk_level.upper()}] {p.path_id}: "
                         f"{p.start_agent} -> {p.end_agent} ({p.total_hops} hops)")
            for h in p.hops:
                lines.append(f"      {h.source_agent} --[{h.method}]--> "
                             f"{h.target_agent} ({h.technique_name})")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: LateralReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"
