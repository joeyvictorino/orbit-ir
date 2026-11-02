"""MITRE ATT&CK tactic progression analysis for agent evidence.

Detects sequential tactic chains in agent behaviour, scores kill-chain
completeness, and flags suspicious tactic jumps that skip expected
intermediate stages.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "exfiltration",
    "command-and-control",
    "impact",
]

TACTIC_INDEX = {t: i for i, t in enumerate(TACTIC_ORDER)}

TOOL_TACTIC_MAP: dict[str, str] = {
    "nmap": "reconnaissance",
    "port_scan": "reconnaissance",
    "whois": "reconnaissance",
    "dns_lookup": "reconnaissance",
    "enumerate_hosts": "reconnaissance",
    "scan_network": "reconnaissance",
    "register_domain": "resource-development",
    "create_account": "resource-development",
    "provision_server": "resource-development",
    "setup_infra": "resource-development",
    "phishing_send": "initial-access",
    "exploit_vuln": "initial-access",
    "brute_force": "initial-access",
    "ssh_login": "initial-access",
    "execute_command": "execution",
    "run_script": "execution",
    "invoke_shell": "execution",
    "exec": "execution",
    "create_service": "persistence",
    "install_backdoor": "persistence",
    "add_startup": "persistence",
    "modify_registry": "persistence",
    "create_role": "privilege-escalation",
    "elevate": "privilege-escalation",
    "assume_role": "privilege-escalation",
    "grant_permission": "privilege-escalation",
    "modify_acl": "privilege-escalation",
    "clear_logs": "defense-evasion",
    "disable_av": "defense-evasion",
    "obfuscate": "defense-evasion",
    "timestomp": "defense-evasion",
    "delete_logs": "defense-evasion",
    "dump_credentials": "credential-access",
    "keylogger": "credential-access",
    "steal_token": "credential-access",
    "harvest_passwords": "credential-access",
    "create_token": "credential-access",
    "list_files": "discovery",
    "enumerate_users": "discovery",
    "read_config": "discovery",
    "whoami": "discovery",
    "list_processes": "discovery",
    "remote_exec": "lateral-movement",
    "pivot": "lateral-movement",
    "move_lateral": "lateral-movement",
    "psexec": "lateral-movement",
    "wmi_exec": "lateral-movement",
    "collect_data": "collection",
    "screenshot": "collection",
    "archive_data": "collection",
    "read_database": "collection",
    "exfiltrate": "exfiltration",
    "upload_data": "exfiltration",
    "dns_tunnel": "exfiltration",
    "send_data": "exfiltration",
    "beacon": "command-and-control",
    "c2_connect": "command-and-control",
    "reverse_shell": "command-and-control",
    "tunnel": "command-and-control",
    "encrypt_data": "impact",
    "wipe_disk": "impact",
    "deface": "impact",
    "destroy_resource": "impact",
    "ransomware": "impact",
}

EFFECT_TACTIC_MAP: dict[str, str] = {
    "recon-performed": "reconnaissance",
    "host-enumerated": "reconnaissance",
    "infra-provisioned": "resource-development",
    "account-created": "resource-development",
    "initial-access-gained": "initial-access",
    "exploit-succeeded": "initial-access",
    "command-executed": "execution",
    "script-run": "execution",
    "persistence-installed": "persistence",
    "backdoor-installed": "persistence",
    "privilege-escalated": "privilege-escalation",
    "role-modified": "privilege-escalation",
    "permission-granted": "privilege-escalation",
    "logs-cleared": "defense-evasion",
    "av-disabled": "defense-evasion",
    "credential-created": "credential-access",
    "credential-stolen": "credential-access",
    "token-minted": "credential-access",
    "credential-rotated": "credential-access",
    "files-listed": "discovery",
    "users-enumerated": "discovery",
    "lateral-move": "lateral-movement",
    "remote-execution": "lateral-movement",
    "data-collected": "collection",
    "data-archived": "collection",
    "data-exfiltrated": "exfiltration",
    "data-uploaded": "exfiltration",
    "c2-established": "command-and-control",
    "beacon-sent": "command-and-control",
    "data-encrypted": "impact",
    "resource-destroyed": "impact",
    "service-disrupted": "impact",
}


def _map_tactic(tool: str, effect: str, tactic_hint: str) -> str | None:
    if tactic_hint and tactic_hint.lower() in TACTIC_INDEX:
        return tactic_hint.lower()
    lower_tool = tool.lower()
    if lower_tool in TOOL_TACTIC_MAP:
        return TOOL_TACTIC_MAP[lower_tool]
    lower_effect = effect.lower()
    if lower_effect in EFFECT_TACTIC_MAP:
        return EFFECT_TACTIC_MAP[lower_effect]
    for keyword, tactic in TOOL_TACTIC_MAP.items():
        if keyword in lower_tool:
            return tactic
    for keyword, tactic in EFFECT_TACTIC_MAP.items():
        if keyword in lower_effect:
            return tactic
    return None


@dataclass
class TacticEvent:
    timestamp: str
    agent_id: str
    tactic: str
    tool: str
    effect: str
    resource: str
    source_file: str
    line: int


@dataclass
class TacticJump:
    from_tactic: str
    to_tactic: str
    skipped: list[str]
    timestamp: str
    agent_id: str


@dataclass
class TacticChain:
    chain_id: str
    agent_id: str
    tactics: list[str]
    events: list[TacticEvent]
    jumps: list[TacticJump] = field(default_factory=list)
    completeness: float = 0.0
    length: int = 0


@dataclass
class TacticChainSummary:
    total_chains: int
    longest_chain: int
    avg_completeness: float
    agents_with_chains: int
    total_jumps: int
    tactics_observed: int
    by_tactic: dict[str, int] = field(default_factory=dict)


@dataclass
class TacticChainReport:
    chains: list[TacticChain]
    summary: TacticChainSummary
    agents_involved: list[str]
    all_events: list[TacticEvent]


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        else:
            try:
                obj = json.loads(text)
                if isinstance(obj, list):
                    events.extend(obj)
                else:
                    events.append(obj)
            except json.JSONDecodeError:
                pass
    return events


def analyze_tactic_chains(
    events: list[dict[str, Any]],
) -> TacticChainReport:
    tactic_events: list[TacticEvent] = []

    for i, ev in enumerate(events):
        agent = ev.get("agent_id", "")
        tool = ev.get("claimed_tool", ev.get("actual_tool", ev.get("tool", "")))
        effect = ev.get("effect", "")
        tactic_hint = ev.get("tactic", "")
        resource = ev.get("resource", "")
        ts = ev.get("timestamp", "")
        src = ev.get("source_file", "events.jsonl")

        tactic = _map_tactic(tool, effect, tactic_hint)
        if tactic:
            tactic_events.append(TacticEvent(
                timestamp=ts,
                agent_id=agent,
                tactic=tactic,
                tool=tool,
                effect=effect,
                resource=resource,
                source_file=src,
                line=i + 1,
            ))

    tactic_events.sort(key=lambda e: e.timestamp)

    by_agent: dict[str, list[TacticEvent]] = defaultdict(list)
    for te in tactic_events:
        by_agent[te.agent_id].append(te)

    chains: list[TacticChain] = []
    for agent, agent_events in sorted(by_agent.items()):
        if not agent_events:
            continue

        seen_tactics: list[str] = []
        for te in agent_events:
            if not seen_tactics or seen_tactics[-1] != te.tactic:
                seen_tactics.append(te.tactic)

        jumps = _detect_jumps(seen_tactics, agent, agent_events)
        completeness = _score_completeness(seen_tactics)

        chains.append(TacticChain(
            chain_id=f"TC-{len(chains)+1:03d}",
            agent_id=agent,
            tactics=seen_tactics,
            events=agent_events,
            jumps=jumps,
            completeness=completeness,
            length=len(seen_tactics),
        ))

    chains.sort(key=lambda c: (-c.completeness, -c.length))

    all_tactics: dict[str, int] = defaultdict(int)
    for te in tactic_events:
        all_tactics[te.tactic] += 1

    total_jumps = sum(len(c.jumps) for c in chains)
    avg_comp = (sum(c.completeness for c in chains) / len(chains)) if chains else 0.0
    longest = max((c.length for c in chains), default=0)

    return TacticChainReport(
        chains=chains,
        summary=TacticChainSummary(
            total_chains=len(chains),
            longest_chain=longest,
            avg_completeness=round(avg_comp, 3),
            agents_with_chains=len(chains),
            total_jumps=total_jumps,
            tactics_observed=len(all_tactics),
            by_tactic=dict(sorted(all_tactics.items(), key=lambda kv: TACTIC_INDEX.get(kv[0], 99))),
        ),
        agents_involved=sorted(set(c.agent_id for c in chains)),
        all_events=tactic_events,
    )


def _detect_jumps(
    tactics: list[str],
    agent: str,
    events: list[TacticEvent],
) -> list[TacticJump]:
    jumps: list[TacticJump] = []
    for i in range(1, len(tactics)):
        prev_idx = TACTIC_INDEX.get(tactics[i - 1], -1)
        curr_idx = TACTIC_INDEX.get(tactics[i], -1)
        if prev_idx < 0 or curr_idx < 0:
            continue
        if curr_idx > prev_idx + 1:
            skipped = TACTIC_ORDER[prev_idx + 1: curr_idx]
            ts = ""
            for e in events:
                if e.tactic == tactics[i]:
                    ts = e.timestamp
                    break
            jumps.append(TacticJump(
                from_tactic=tactics[i - 1],
                to_tactic=tactics[i],
                skipped=skipped,
                timestamp=ts,
                agent_id=agent,
            ))
    return jumps


def _score_completeness(tactics: list[str]) -> float:
    if not tactics:
        return 0.0
    unique = set(tactics)
    return round(len(unique) / len(TACTIC_ORDER), 3)


def format_text(report: TacticChainReport) -> str:
    lines: list[str] = []
    lines.append("MITRE ATT&CK Tactic Chain Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Tactic chains:          {s.total_chains}")
    lines.append(f"  Longest chain:          {s.longest_chain}")
    lines.append(f"  Avg completeness:       {s.avg_completeness:.1%}")
    lines.append(f"  Agents with chains:     {s.agents_with_chains}")
    lines.append(f"  Total tactic jumps:     {s.total_jumps}")
    lines.append(f"  Tactics observed:       {s.tactics_observed}")
    lines.append("")

    if s.by_tactic:
        lines.append("  Tactic Distribution:")
        lines.append("  " + "-" * 60)
        for tactic, count in s.by_tactic.items():
            lines.append(f"    {tactic:<28} {count}")
        lines.append("")

    if report.chains:
        lines.append("  Chains:")
        lines.append("  " + "-" * 60)
        for c in report.chains:
            lines.append(f"  {c.chain_id}: agent={c.agent_id}  length={c.length}  completeness={c.completeness:.1%}")
            lines.append(f"    Tactics: {' -> '.join(c.tactics)}")
            if c.jumps:
                for j in c.jumps:
                    lines.append(f"    JUMP: {j.from_tactic} -> {j.to_tactic} (skipped: {', '.join(j.skipped)})")
            lines.append(f"    Events: {len(c.events)}")
            for ev in c.events[:10]:
                lines.append(f"      - {ev.timestamp}: [{ev.tactic}] {ev.tool} on {ev.resource}")
            if len(c.events) > 10:
                lines.append(f"      ... and {len(c.events) - 10} more")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: TacticChainReport) -> str:
    data = {
        "chains": [
            {
                "chain_id": c.chain_id,
                "agent_id": c.agent_id,
                "tactics": c.tactics,
                "completeness": c.completeness,
                "length": c.length,
                "jumps": [asdict(j) for j in c.jumps],
                "events": [asdict(e) for e in c.events],
            }
            for c in report.chains
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
