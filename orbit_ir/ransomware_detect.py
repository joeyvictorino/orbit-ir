"""Ransomware behavior detection for AI agent environments."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


RANSOM_EXTENSIONS = {
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".locky",
    ".cerber", ".zepto", ".odin", ".thor", ".zzzzz", ".micro",
    ".cryptowall", ".crinf", ".r5a", ".xrtn", ".xtbl", ".aaa",
}

RANSOM_NOTE_PATTERNS = {
    "readme.txt", "decrypt.txt", "how_to_decrypt", "ransom_note",
    "restore_files", "help_decrypt", "recovery_key", "your_files",
    "pay_ransom", "decrypt_instructions", "important.txt",
}

SHADOW_DELETE_PATTERNS = {
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set", "wbadmin delete catalog",
}


@dataclass
class Detection:
    category: str
    severity: str
    agent: str
    description: str
    evidence: list[str] = field(default_factory=list)
    timestamp: str = ""


def _is_file_event(event: dict[str, Any]) -> bool:
    action = str(event.get("action", "")).lower()
    tool = str(event.get("tool", "")).lower()
    return any(k in action or k in tool for k in ("write", "file", "create", "rename", "modify"))


def _has_ransom_extension(event: dict[str, Any]) -> bool:
    for key in ("path", "file", "target", "destination", "filename"):
        val = str(event.get(key, "")).lower()
        for ext in RANSOM_EXTENSIONS:
            if val.endswith(ext):
                return True
    return False


def _is_ransom_note(event: dict[str, Any]) -> bool:
    for key in ("path", "file", "target", "filename"):
        val = str(event.get(key, "")).lower()
        for pat in RANSOM_NOTE_PATTERNS:
            if pat in val:
                return True
    return False


def _is_shadow_delete(event: dict[str, Any]) -> bool:
    cmd = str(event.get("command", "")).lower()
    action = str(event.get("action", "")).lower()
    combined = cmd + " " + action
    for pat in SHADOW_DELETE_PATTERNS:
        if pat in combined:
            return True
    return False


def _is_mass_encryption(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    agent_events = [e for e in events if str(e.get("agent", "")) == agent and _is_file_event(e)]
    ext_changes = [e for e in agent_events if _has_ransom_extension(e)]
    if len(ext_changes) >= 5:
        detections.append(Detection(
            category="mass_encryption",
            severity="critical",
            agent=agent,
            description=f"Mass file encryption: {len(ext_changes)} files renamed to ransomware extensions",
            evidence=[str(e.get("path", e.get("file", ""))) for e in ext_changes[:5]],
        ))
    return detections


def _detect_ransom_notes(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) == agent and _is_file_event(e) and _is_ransom_note(e):
            detections.append(Detection(
                category="ransom_note",
                severity="critical",
                agent=agent,
                description="Ransom note file created",
                evidence=[str(e.get("path", e.get("file", "")))],
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_shadow_deletion(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) == agent and _is_shadow_delete(e):
            detections.append(Detection(
                category="shadow_delete",
                severity="critical",
                agent=agent,
                description="Shadow copy or backup deletion attempt",
                evidence=[str(e.get("command", e.get("action", "")))],
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_c2_beacon(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    net_events = [e for e in events
                  if str(e.get("agent", "")) == agent
                  and any(k in str(e.get("action", "")).lower() or k in str(e.get("tool", "")).lower()
                         for k in ("http", "network", "connect", "request", "curl", "wget"))]
    encrypt_events = [e for e in events
                      if str(e.get("agent", "")) == agent and _has_ransom_extension(e)]
    if encrypt_events and net_events:
        post_encrypt_nets = [n for n in net_events
                            for enc in encrypt_events
                            if str(n.get("timestamp", "")) >= str(enc.get("timestamp", ""))]
        if post_encrypt_nets:
            detections.append(Detection(
                category="c2_beacon",
                severity="high",
                agent=agent,
                description="Network beacon detected after encryption activity",
                evidence=[str(n.get("url", n.get("target", ""))) for n in post_encrypt_nets[:3]],
            ))
    return detections


def analyze_ransomware(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"detections": [], "summary": {"total": 0, "by_category": {}, "agents_affected": 0}}

    agents = {str(e.get("agent", "unknown")) for e in events}
    all_detections: list[Detection] = []

    for agent in agents:
        all_detections.extend(_is_mass_encryption(events, agent))
        all_detections.extend(_detect_ransom_notes(events, agent))
        all_detections.extend(_detect_shadow_deletion(events, agent))
        all_detections.extend(_detect_c2_beacon(events, agent))

    by_category: dict[str, int] = {}
    agents_hit: set[str] = set()
    for d in all_detections:
        by_category[d.category] = by_category.get(d.category, 0) + 1
        agents_hit.add(d.agent)

    max_sev = "none"
    for d in all_detections:
        if d.severity == "critical":
            max_sev = "critical"
            break
        if d.severity == "high" and max_sev != "critical":
            max_sev = "high"

    return {
        "detections": [
            {"category": d.category, "severity": d.severity, "agent": d.agent,
             "description": d.description, "evidence": d.evidence, "timestamp": d.timestamp}
            for d in all_detections
        ],
        "summary": {
            "total": len(all_detections),
            "by_category": by_category,
            "agents_affected": len(agents_hit),
            "max_severity": max_sev,
        },
    }


def format_text(report: dict[str, Any]) -> str:
    lines = ["Ransomware Behavior Detection", "=" * 40, ""]
    s = report.get("summary", {})
    lines.append(f"  Total detections: {s.get('total', 0)}")
    lines.append(f"  Agents affected:  {s.get('agents_affected', 0)}")
    lines.append(f"  Max severity:     {s.get('max_severity', 'none')}")
    lines.append("")
    for d in report.get("detections", []):
        lines.append(f"  [{d['severity'].upper()}] {d['category']}: {d['description']}")
        if d.get("evidence"):
            for ev in d["evidence"][:3]:
                lines.append(f"    - {ev}")
    lines.append("")
    return "\n".join(lines)


def format_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


def _load_events(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "events" in data:
            return data["events"]
        return [data]
    return []
