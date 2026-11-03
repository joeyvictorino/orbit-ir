"""DLL injection and process injection detection for AI agent environments."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


INJECTION_APIS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory",
    "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
    "queueuserapc", "ntqueueapcthread", "setthreadcontext",
    "ntunmapviewofsection", "zwunmapviewofsection",
}

SUSPICIOUS_DLLS = {
    "ntdll.dll", "kernel32.dll", "advapi32.dll", "user32.dll",
    "ws2_32.dll", "wininet.dll", "urlmon.dll", "shell32.dll",
}

HOLLOWING_PATTERNS = {
    "ntunmapviewofsection", "zwunmapviewofsection",
    "process hollowing", "runpe", "process doppelganging",
}

REFLECTIVE_PATTERNS = {
    "reflective", "loadlibrary", "getprocaddress",
    "pe injection", "manual map", "module stomping",
}

PROCESS_NAMES_TARGET = {
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "spoolsv.exe", "taskhost.exe",
    "notepad.exe", "calc.exe",
}


@dataclass
class Detection:
    category: str
    severity: str
    agent: str
    description: str
    evidence: list[str] = field(default_factory=list)
    timestamp: str = ""


def _event_text(event: dict[str, Any]) -> str:
    parts = []
    for key in ("action", "tool", "command", "api_call", "function", "description", "details"):
        val = str(event.get(key, ""))
        if val:
            parts.append(val)
    return " ".join(parts).lower()


def _detect_api_injection(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [api for api in INJECTION_APIS if api in text]
        if found:
            detections.append(Detection(
                category="api_injection",
                severity="critical",
                agent=agent,
                description=f"Process injection API call detected: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_dll_load(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        if "loadlibrary" in text or "dll" in text:
            for key in ("path", "file", "target", "module", "dll"):
                val = str(e.get(key, "")).lower()
                if any(dll in val for dll in SUSPICIOUS_DLLS):
                    detections.append(Detection(
                        category="suspicious_dll_load",
                        severity="high",
                        agent=agent,
                        description=f"Suspicious DLL load: {val}",
                        evidence=[val],
                        timestamp=str(e.get("timestamp", "")),
                    ))
                    break
    return detections


def _detect_process_hollowing(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in HOLLOWING_PATTERNS if p in text]
        if found:
            target = ""
            for key in ("target", "process", "pid", "path"):
                v = str(e.get(key, ""))
                if v:
                    target = v
                    break
            detections.append(Detection(
                category="process_hollowing",
                severity="critical",
                agent=agent,
                description=f"Process hollowing indicators: {', '.join(found)}",
                evidence=found + ([target] if target else []),
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_reflective_injection(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in REFLECTIVE_PATTERNS if p in text]
        if len(found) >= 2:
            detections.append(Detection(
                category="reflective_injection",
                severity="critical",
                agent=agent,
                description=f"Reflective injection indicators: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_target_process(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        has_inject = any(api in text for api in INJECTION_APIS) or "inject" in text
        if not has_inject:
            continue
        for key in ("target", "process", "path", "pid_name"):
            val = str(e.get(key, "")).lower()
            matched = [p for p in PROCESS_NAMES_TARGET if p in val]
            if matched:
                detections.append(Detection(
                    category="target_process_injection",
                    severity="critical",
                    agent=agent,
                    description=f"Injection targeting system process: {', '.join(matched)}",
                    evidence=matched,
                    timestamp=str(e.get("timestamp", "")),
                ))
                break
    return detections


def _detect_shellcode_patterns(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    shellcode_indicators = {"shellcode", "payload", "\\x90\\x90", "nop sled", "egg hunter", "staged payload"}
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [s for s in shellcode_indicators if s in text]
        if found:
            detections.append(Detection(
                category="shellcode_detected",
                severity="critical",
                agent=agent,
                description=f"Shellcode indicators: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def analyze_dll_injection(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"detections": [], "summary": {"total": 0, "by_category": {}, "agents_affected": 0}}

    agents = {str(e.get("agent", "unknown")) for e in events}
    all_detections: list[Detection] = []

    for agent in agents:
        all_detections.extend(_detect_api_injection(events, agent))
        all_detections.extend(_detect_dll_load(events, agent))
        all_detections.extend(_detect_process_hollowing(events, agent))
        all_detections.extend(_detect_reflective_injection(events, agent))
        all_detections.extend(_detect_target_process(events, agent))
        all_detections.extend(_detect_shellcode_patterns(events, agent))

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
    lines = ["DLL/Process Injection Detection", "=" * 40, ""]
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
