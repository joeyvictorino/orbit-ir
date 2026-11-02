"""Persistence mechanism detection for agent evidence.

Analyzes agent event sequences to detect patterns consistent with
establishing persistence—scheduled tasks, service installation,
credential creation, config modification, and auto-start mechanisms.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


PERSISTENCE_TYPES = {
    "scheduled": "Scheduled task or cron job for recurring execution",
    "service-based": "Service or daemon installed for persistent execution",
    "credential-based": "Credential created or injected for future access",
    "config-based": "Configuration modified to enable auto-start or access",
}

SCHEDULED_TOOLS = {
    "create_cron", "modify_cron", "schedule_task", "create_timer",
    "add_crontab", "register_schedule", "create_job", "at_command",
    "create_scheduled_task", "schtasks",
}

SERVICE_TOOLS = {
    "install_service", "create_service", "register_daemon",
    "systemctl_enable", "service_install", "add_startup",
    "create_init_script", "register_autostart", "install_agent",
    "deploy_service",
}

CREDENTIAL_TOOLS = {
    "create_user", "add_account", "create_ssh_key", "inject_key",
    "add_authorized_key", "create_api_key", "register_webhook",
    "create_token", "add_backdoor_user", "modify_passwd",
    "create_certificate", "register_oauth_app",
}

CONFIG_TOOLS = {
    "modify_config", "edit_startup", "modify_registry",
    "write_profile", "modify_bashrc", "edit_init",
    "modify_autostart", "write_launchd", "modify_sudoers",
    "edit_hosts", "modify_pam",
}

PERSISTENCE_RESOURCES = re.compile(
    r"(cron|crontab|systemd|launchd|init\.d|rc\.local|autostart|startup|"
    r"registry|scheduled.?task|at\.allow|sudoers|authorized_keys|"
    r"\.bashrc|\.profile|\.ssh|webhook|daemon|service)",
    re.IGNORECASE,
)

PERSISTENCE_EFFECTS = {
    "cron-created", "cron-modified", "service-installed",
    "service-enabled", "account-created", "key-injected",
    "key-created", "webhook-registered", "config-modified",
    "autostart-added", "daemon-registered", "token-created",
    "ssh-key-added", "api-key-created", "schedule-created",
}


@dataclass
class PersistenceDetection:
    detection_id: str
    agent_id: str
    persistence_type: str
    mechanism: str
    strength: str  # low, medium, high
    stealth: str   # low, medium, high
    confidence: str
    timestamp: str
    tool_used: str
    resource: str
    effect: str
    description: str


@dataclass
class PersistenceSummary:
    total_detections: int
    by_type: dict[str, int]
    by_strength: dict[str, int]
    by_stealth: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int


@dataclass
class PersistenceReport:
    detections: list[PersistenceDetection]
    persistence_map: dict[str, list[str]]
    summary: PersistenceSummary
    agents_involved: list[str]


def _get_tool(ev: dict[str, Any]) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))


def _classify_persistence_type(tool: str, resource: str, effect: str) -> str | None:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    lower_effect = effect.lower()

    if lower_tool in SCHEDULED_TOOLS or any(k in lower_tool for k in {"cron", "schedule", "timer"}):
        return "scheduled"
    if lower_tool in SERVICE_TOOLS or any(k in lower_tool for k in {"service", "daemon", "systemctl"}):
        return "service-based"
    if lower_tool in CREDENTIAL_TOOLS or any(k in lower_tool for k in {"ssh_key", "api_key", "create_user", "webhook"}):
        return "credential-based"
    if lower_tool in CONFIG_TOOLS or any(k in lower_tool for k in {"bashrc", "profile", "autostart", "registry", "sudoers"}):
        return "config-based"

    if any(k in lower_effect for k in {"cron", "schedule"}):
        return "scheduled"
    if any(k in lower_effect for k in {"service", "daemon"}):
        return "service-based"
    if any(k in lower_effect for k in {"key", "token", "account", "webhook"}):
        return "credential-based"
    if any(k in lower_effect for k in {"config", "autostart"}):
        return "config-based"

    if PERSISTENCE_RESOURCES.search(resource):
        if any(k in lower_resource for k in {"cron", "schedule", "timer", "at.allow"}):
            return "scheduled"
        if any(k in lower_resource for k in {"service", "daemon", "init.d", "systemd", "launchd"}):
            return "service-based"
        if any(k in lower_resource for k in {"ssh", "authorized_keys", "webhook", "token"}):
            return "credential-based"
        return "config-based"

    if lower_effect in PERSISTENCE_EFFECTS:
        for eff_key, ptype in [
            ("cron", "scheduled"), ("schedule", "scheduled"),
            ("service", "service-based"), ("daemon", "service-based"),
            ("key", "credential-based"), ("token", "credential-based"),
            ("account", "credential-based"), ("webhook", "credential-based"),
        ]:
            if eff_key in lower_effect:
                return ptype
        return "config-based"

    return None


def _score_strength(ptype: str, tool: str, resource: str) -> str:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    if ptype == "service-based":
        if any(k in lower_resource for k in {"systemd", "init.d", "launchd"}):
            return "high"
        return "medium"
    if ptype == "credential-based":
        if any(k in lower_tool for k in {"ssh_key", "authorized_key", "create_certificate"}):
            return "high"
        if any(k in lower_tool for k in {"api_key", "webhook", "create_token"}):
            return "medium"
        return "medium"
    if ptype == "scheduled":
        if any(k in lower_resource for k in {"crontab", "systemd"}):
            return "high"
        return "medium"
    if ptype == "config-based":
        if any(k in lower_resource for k in {"sudoers", "pam", "registry"}):
            return "high"
        if any(k in lower_resource for k in {"bashrc", "profile"}):
            return "medium"
        return "low"
    return "low"


def _score_stealth(ptype: str, tool: str, resource: str) -> str:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    if any(k in lower_tool for k in {"backdoor", "inject", "hidden"}):
        return "high"
    if ptype == "config-based":
        if any(k in lower_resource for k in {"bashrc", "profile", "rc.local"}):
            return "high"
        return "medium"
    if ptype == "credential-based":
        if any(k in lower_tool for k in {"inject_key", "add_authorized_key"}):
            return "high"
        return "medium"
    if ptype == "scheduled":
        return "medium"
    if ptype == "service-based":
        return "low"
    return "low"


def _score_confidence(ptype: str | None, tool: str, resource: str, effect: str) -> str:
    lower_tool = tool.lower()
    lower_effect = effect.lower()
    if lower_tool in SCHEDULED_TOOLS | SERVICE_TOOLS | CREDENTIAL_TOOLS | CONFIG_TOOLS:
        return "high"
    if lower_effect in PERSISTENCE_EFFECTS:
        return "high"
    if PERSISTENCE_RESOURCES.search(resource):
        return "medium"
    return "low"


def _describe_mechanism(ptype: str, tool: str, resource: str) -> str:
    if ptype == "scheduled":
        return f"scheduled execution via {tool} on {resource}" if resource else f"scheduled execution via {tool}"
    if ptype == "service-based":
        return f"service installation via {tool} targeting {resource}" if resource else f"service installation via {tool}"
    if ptype == "credential-based":
        return f"credential persistence via {tool} for {resource}" if resource else f"credential persistence via {tool}"
    if ptype == "config-based":
        return f"configuration persistence via {tool} modifying {resource}" if resource else f"configuration persistence via {tool}"
    return f"persistence action via {tool}"


def analyze_persistence(events: list[dict[str, Any]]) -> PersistenceReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[PersistenceDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        for ev in evts_sorted:
            tool = _get_tool(ev)
            resource = ev.get("resource", "")
            effect = ev.get("effect", "")
            ts = ev.get("timestamp", "")

            ptype = _classify_persistence_type(tool, resource, effect)
            if ptype is None:
                continue

            det_counter += 1
            strength = _score_strength(ptype, tool, resource)
            stealth = _score_stealth(ptype, tool, resource)
            confidence = _score_confidence(ptype, tool, resource, effect)
            mechanism = _describe_mechanism(ptype, tool, resource)

            detections.append(PersistenceDetection(
                detection_id=f"PERSIST-{det_counter:03d}",
                agent_id=agent,
                persistence_type=ptype,
                mechanism=mechanism,
                strength=strength,
                stealth=stealth,
                confidence=confidence,
                timestamp=ts,
                tool_used=tool,
                resource=resource,
                effect=effect,
                description=f"Agent '{agent}' established {ptype} persistence: {mechanism}",
            ))

    detections.sort(key=lambda d: (
        {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3),
        {"high": 0, "medium": 1, "low": 2}.get(d.strength, 3),
    ))

    persistence_map: dict[str, list[str]] = defaultdict(list)
    for d in detections:
        persistence_map[d.agent_id].append(d.persistence_type)
    persistence_map_plain = {k: sorted(set(v)) for k, v in persistence_map.items()}

    all_agents = sorted({d.agent_id for d in detections})
    type_counts: dict[str, int] = defaultdict(int)
    strength_counts: dict[str, int] = defaultdict(int)
    stealth_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    for d in detections:
        type_counts[d.persistence_type] += 1
        strength_counts[d.strength] += 1
        stealth_counts[d.stealth] += 1
        conf_counts[d.confidence] += 1

    return PersistenceReport(
        detections=detections,
        persistence_map=persistence_map_plain,
        summary=PersistenceSummary(
            total_detections=len(detections),
            by_type=dict(type_counts),
            by_strength=dict(strength_counts),
            by_stealth=dict(stealth_counts),
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


def format_text(report: PersistenceReport) -> str:
    lines: list[str] = []
    lines.append("Persistence Mechanism Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append("")

    if s.by_type:
        lines.append("  By Type:")
        for ptype, count in sorted(s.by_type.items()):
            desc = PERSISTENCE_TYPES.get(ptype, ptype)
            lines.append(f"    {ptype}: {count} ({desc})")
        lines.append("")

    if s.by_strength:
        lines.append("  By Strength:")
        for strength, count in sorted(s.by_strength.items()):
            lines.append(f"    {strength}: {count}")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.confidence.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Type: {d.persistence_type}")
        lines.append(f"    Mechanism: {d.mechanism}")
        lines.append(f"    Strength: {d.strength}, Stealth: {d.stealth}")
        lines.append(f"    Tool: {d.tool_used}")
        if d.resource:
            lines.append(f"    Resource: {d.resource}")
        lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    if report.persistence_map:
        lines.append("  Persistence Map:")
        lines.append("  " + "-" * 58)
        for agent, ptypes in sorted(report.persistence_map.items()):
            lines.append(f"    {agent}: {', '.join(ptypes)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: PersistenceReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "persistence_map": report.persistence_map,
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
