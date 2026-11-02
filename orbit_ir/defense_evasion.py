"""Defense evasion technique identification for agent evidence.

Analyzes agent event sequences to detect defense evasion patterns—log
deletion, timestamp manipulation, process hiding, tool masquerading,
encoding/obfuscation, disabling security controls, and clearing audit trails.
Maps detections to MITRE ATT&CK Defense Evasion techniques.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MITRE_TECHNIQUES = {
    "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.002": "Clear Linux/Mac System Logs",
    "T1070.003": "Clear Command History",
    "T1070.004": "File Deletion",
    "T1070.006": "Timestomp",
    "T1036": "Masquerading",
    "T1036.003": "Rename System Utilities",
    "T1036.005": "Match Legitimate Name or Location",
    "T1027": "Obfuscated Files or Information",
    "T1027.001": "Binary Padding",
    "T1027.010": "Command Obfuscation",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
    "T1562.006": "Indicator Blocking",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1218": "System Binary Proxy Execution",
}

LOG_DELETION_TOOLS = {
    "delete_log", "clear_log", "truncate_log", "remove_log",
    "shred_file", "wipe_log", "purge_log", "rm_log",
    "clear_history", "delete_history", "clear_audit",
    "delete_events", "clear_events",
}

LOG_DELETION_RESOURCES = re.compile(
    r"(\.log$|/log/|syslog|auth\.log|messages|journal|event.?log|"
    r"\.bash_history|\.zsh_history|history|audit\.log|wtmp|btmp|lastlog|"
    r"secure|kern\.log|access\.log|error\.log)",
    re.IGNORECASE,
)

TIMESTAMP_TOOLS = {
    "touch", "timestomp", "modify_timestamp", "set_time",
    "change_mtime", "alter_timestamp", "utime", "futimes",
}

MASQUERADE_TOOLS = {
    "rename", "copy_as", "alias", "symlink", "move",
    "disguise", "masquerade", "impersonate_tool",
}

MASQUERADE_INDICATORS = re.compile(
    r"(svchost|lsass|csrss|explorer|chrome|firefox|systemd|"
    r"kworker|migration|update|patch|helper|agent|service)",
    re.IGNORECASE,
)

ENCODING_TOOLS = {
    "base64_encode", "encode", "obfuscate", "encrypt",
    "xor_encode", "rot13", "hex_encode", "compress",
    "pack", "cipher", "scramble",
}

SECURITY_DISABLE_TOOLS = {
    "disable_antivirus", "stop_firewall", "disable_logging",
    "modify_selinux", "disable_apparmor", "stop_auditd",
    "disable_ids", "stop_monitoring", "disable_defender",
    "uninstall_agent", "kill_process", "disable_security",
    "modify_iptables", "flush_rules",
}

AUDIT_CLEAR_EFFECTS = {
    "log-deleted", "log-cleared", "log-truncated",
    "history-cleared", "audit-cleared", "events-deleted",
    "trail-cleared", "evidence-destroyed",
}

EVASION_EFFECTS = {
    "timestamp-modified", "file-renamed", "process-hidden",
    "tool-renamed", "command-obfuscated", "security-disabled",
    "firewall-disabled", "logging-disabled", "ids-disabled",
    "monitoring-stopped", "antivirus-disabled",
}


@dataclass
class EvasionDetection:
    detection_id: str
    agent_id: str
    technique_id: str
    technique_name: str
    sub_technique: str
    confidence: str
    timestamp: str
    tool_used: str
    resource: str
    effect: str
    description: str


@dataclass
class TechniqueMapping:
    technique_id: str
    technique_name: str
    detection_count: int
    agents: list[str]
    confidence_distribution: dict[str, int]


@dataclass
class EvasionSummary:
    total_detections: int
    unique_techniques: int
    by_technique: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int


@dataclass
class EvasionReport:
    detections: list[EvasionDetection]
    technique_mapping: list[TechniqueMapping]
    summary: EvasionSummary
    agents_involved: list[str]


def _get_tool(ev: dict[str, Any]) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))


def _classify_evasion(tool: str, resource: str, effect: str) -> tuple[str, str] | None:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    lower_effect = effect.lower()

    if lower_tool in LOG_DELETION_TOOLS or lower_effect in AUDIT_CLEAR_EFFECTS:
        if any(k in lower_resource for k in {"history", "bash_history", "zsh_history"}):
            return ("T1070.003", "Clear Command History")
        if any(k in lower_resource for k in {"event", "windows"}):
            return ("T1070.001", "Clear Windows Event Logs")
        if LOG_DELETION_RESOURCES.search(resource):
            return ("T1070.002", "Clear Linux/Mac System Logs")
        return ("T1070", "Indicator Removal")

    if any(k in lower_tool for k in {"delete_file", "shred", "wipe"}) and any(
        k in lower_resource for k in {"evidence", "forensic", "artifact", "trace"}
    ):
        return ("T1070.004", "File Deletion")

    if LOG_DELETION_RESOURCES.search(resource) and any(k in lower_tool for k in {"delete", "remove", "clear", "truncate", "shred", "wipe", "rm"}):
        return ("T1070", "Indicator Removal")

    if lower_tool in TIMESTAMP_TOOLS or lower_effect == "timestamp-modified":
        return ("T1070.006", "Timestomp")

    if lower_tool in MASQUERADE_TOOLS and (MASQUERADE_INDICATORS.search(resource) or lower_effect in {"file-renamed", "tool-renamed"}):
        if any(k in lower_tool for k in {"rename", "copy_as", "disguise"}):
            return ("T1036.003", "Rename System Utilities")
        return ("T1036", "Masquerading")

    if lower_effect in {"file-renamed", "tool-renamed", "process-hidden"}:
        return ("T1036.005", "Match Legitimate Name or Location")

    if lower_tool in ENCODING_TOOLS or lower_effect == "command-obfuscated":
        return ("T1027.010", "Command Obfuscation")

    if lower_tool in SECURITY_DISABLE_TOOLS:
        if any(k in lower_tool for k in {"firewall", "iptables", "flush_rules"}):
            return ("T1562.004", "Disable or Modify System Firewall")
        if any(k in lower_tool for k in {"logging", "auditd", "event"}):
            return ("T1562.002", "Disable Windows Event Logging")
        if any(k in lower_tool for k in {"antivirus", "defender", "ids", "monitoring", "security"}):
            return ("T1562.001", "Disable or Modify Tools")
        return ("T1562", "Impair Defenses")

    if lower_effect in {"security-disabled", "firewall-disabled", "logging-disabled",
                         "ids-disabled", "monitoring-stopped", "antivirus-disabled"}:
        if "firewall" in lower_effect:
            return ("T1562.004", "Disable or Modify System Firewall")
        if "logging" in lower_effect:
            return ("T1562.002", "Disable Windows Event Logging")
        return ("T1562.001", "Disable or Modify Tools")

    return None


def _score_confidence(technique_id: str, tool: str, resource: str, effect: str) -> str:
    lower_tool = tool.lower()
    lower_effect = effect.lower()

    all_known_tools = (
        LOG_DELETION_TOOLS | TIMESTAMP_TOOLS | MASQUERADE_TOOLS
        | ENCODING_TOOLS | SECURITY_DISABLE_TOOLS
    )
    if lower_tool in all_known_tools:
        return "high"
    if lower_effect in AUDIT_CLEAR_EFFECTS | EVASION_EFFECTS:
        return "high"
    if LOG_DELETION_RESOURCES.search(resource) and any(k in lower_tool for k in {"delete", "clear", "rm"}):
        return "medium"
    return "low"


def analyze_defense_evasion(events: list[dict[str, Any]]) -> EvasionReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[EvasionDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        for ev in evts_sorted:
            tool = _get_tool(ev)
            resource = ev.get("resource", "")
            effect = ev.get("effect", "")
            ts = ev.get("timestamp", "")

            result = _classify_evasion(tool, resource, effect)
            if result is None:
                continue

            technique_id, technique_name = result
            det_counter += 1
            confidence = _score_confidence(technique_id, tool, resource, effect)

            parent_id = technique_id.split(".")[0]
            sub_technique = technique_id if "." in technique_id else ""

            detections.append(EvasionDetection(
                detection_id=f"EVASION-{det_counter:03d}",
                agent_id=agent,
                technique_id=technique_id,
                technique_name=technique_name,
                sub_technique=sub_technique,
                confidence=confidence,
                timestamp=ts,
                tool_used=tool,
                resource=resource,
                effect=effect,
                description=f"Agent '{agent}' performed defense evasion ({technique_name}) via {tool}",
            ))

    detections.sort(key=lambda d: (
        {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3),
        d.technique_id,
    ))

    technique_map: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "agents": set(), "conf": defaultdict(int)}
    )
    for d in detections:
        tid = d.technique_id
        technique_map[tid]["count"] += 1
        technique_map[tid]["agents"].add(d.agent_id)
        technique_map[tid]["conf"][d.confidence] += 1

    technique_mappings: list[TechniqueMapping] = []
    for tid, info in sorted(technique_map.items()):
        technique_mappings.append(TechniqueMapping(
            technique_id=tid,
            technique_name=MITRE_TECHNIQUES.get(tid, tid),
            detection_count=info["count"],
            agents=sorted(info["agents"]),
            confidence_distribution=dict(info["conf"]),
        ))

    all_agents = sorted({d.agent_id for d in detections})
    tech_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    for d in detections:
        tech_counts[d.technique_id] += 1
        conf_counts[d.confidence] += 1

    return EvasionReport(
        detections=detections,
        technique_mapping=technique_mappings,
        summary=EvasionSummary(
            total_detections=len(detections),
            unique_techniques=len(technique_map),
            by_technique=dict(tech_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
        ),
        agents_involved=all_agents,
    )


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


def format_text(report: EvasionReport) -> str:
    lines: list[str] = []
    lines.append("Defense Evasion Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Unique techniques:      {s.unique_techniques}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if s.by_technique:
        lines.append("  By MITRE Technique:")
        for tid, count in sorted(s.by_technique.items()):
            name = MITRE_TECHNIQUES.get(tid, tid)
            lines.append(f"    {tid} ({name}): {count}")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.confidence.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Technique: {d.technique_id} - {d.technique_name}")
        if d.sub_technique:
            lines.append(f"    Sub-technique: {d.sub_technique}")
        lines.append(f"    Tool: {d.tool_used}")
        if d.resource:
            lines.append(f"    Resource: {d.resource}")
        if d.effect:
            lines.append(f"    Effect: {d.effect}")
        lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    if report.technique_mapping:
        lines.append("  Technique Summary:")
        lines.append("  " + "-" * 58)
        for tm in report.technique_mapping:
            lines.append(f"    {tm.technique_id} ({tm.technique_name}): {tm.detection_count} detections")
            lines.append(f"      Agents: {', '.join(tm.agents)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: EvasionReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "technique_mapping": [asdict(tm) for tm in report.technique_mapping],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
