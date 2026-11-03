"""Code signing bypass and integrity violation detection for AI agent environments."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


SIGNING_DISABLE_PATTERNS = {
    "set-executionpolicy unrestricted", "set-executionpolicy bypass",
    "set-executionpolicy remotesigned", "-executionpolicy bypass",
    "powershell -ep bypass", "powershell -nop",
}

CERT_TAMPERING_PATTERNS = {
    "certutil", "certmgr", "signtool", "makecert",
    "self-signed", "trust store", "root ca",
    "remove certificate", "delete certificate",
}

INTEGRITY_BYPASS_PATTERNS = {
    "sfc /scannow", "dism", "bcdedit",
    "disable driver signing", "testsigning on",
    "nointegritychecks", "disable integrity",
}

UNSIGNED_EXEC_INDICATORS = {
    "unsigned", "invalid signature", "signature not found",
    "certificate expired", "untrusted publisher",
    "certificate revoked", "hash mismatch",
}

APPLOCKER_BYPASS_PATTERNS = {
    "applocker", "wdac", "device guard",
    "constrained language mode", "bypass policy",
    "code integrity", "ci policy",
}

DLL_SIDELOAD_PATTERNS = {
    "dll sideload", "dll hijack", "search order hijack",
    "phantom dll", "dll proxy", "dll redirection",
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
    for key in ("action", "tool", "command", "description", "details", "output", "error"):
        val = str(event.get(key, ""))
        if val:
            parts.append(val)
    return " ".join(parts).lower()


def _detect_signing_disable(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in SIGNING_DISABLE_PATTERNS if p in text]
        if found:
            detections.append(Detection(
                category="signing_disabled",
                severity="critical",
                agent=agent,
                description=f"Code signing enforcement disabled: {found[0]}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_cert_tampering(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in CERT_TAMPERING_PATTERNS if p in text]
        if len(found) >= 1:
            sev = "critical" if any(k in text for k in ("delete", "remove", "self-signed")) else "high"
            detections.append(Detection(
                category="cert_tampering",
                severity=sev,
                agent=agent,
                description=f"Certificate store manipulation: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_integrity_bypass(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in INTEGRITY_BYPASS_PATTERNS if p in text]
        if found:
            detections.append(Detection(
                category="integrity_bypass",
                severity="critical",
                agent=agent,
                description=f"System integrity check bypass: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_unsigned_execution(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in UNSIGNED_EXEC_INDICATORS if p in text]
        if found:
            exec_path = ""
            for key in ("path", "file", "target", "binary", "executable"):
                v = str(e.get(key, ""))
                if v:
                    exec_path = v
                    break
            detections.append(Detection(
                category="unsigned_execution",
                severity="high",
                agent=agent,
                description=f"Unsigned or invalid code execution: {', '.join(found)}",
                evidence=found + ([exec_path] if exec_path else []),
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_applocker_bypass(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        has_bypass = "bypass" in text or "disable" in text or "circumvent" in text
        has_policy = any(p in text for p in APPLOCKER_BYPASS_PATTERNS)
        if has_bypass and has_policy:
            found = [p for p in APPLOCKER_BYPASS_PATTERNS if p in text]
            detections.append(Detection(
                category="applocker_bypass",
                severity="critical",
                agent=agent,
                description=f"Application control bypass: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def _detect_dll_sideloading(events: list[dict[str, Any]], agent: str) -> list[Detection]:
    detections = []
    for e in events:
        if str(e.get("agent", "")) != agent:
            continue
        text = _event_text(e)
        found = [p for p in DLL_SIDELOAD_PATTERNS if p in text]
        if found:
            detections.append(Detection(
                category="dll_sideloading",
                severity="high",
                agent=agent,
                description=f"DLL sideloading indicators: {', '.join(found)}",
                evidence=found,
                timestamp=str(e.get("timestamp", "")),
            ))
    return detections


def analyze_code_signing(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"detections": [], "summary": {"total": 0, "by_category": {}, "agents_affected": 0}}

    agents = {str(e.get("agent", "unknown")) for e in events}
    all_detections: list[Detection] = []

    for agent in agents:
        all_detections.extend(_detect_signing_disable(events, agent))
        all_detections.extend(_detect_cert_tampering(events, agent))
        all_detections.extend(_detect_integrity_bypass(events, agent))
        all_detections.extend(_detect_unsigned_execution(events, agent))
        all_detections.extend(_detect_applocker_bypass(events, agent))
        all_detections.extend(_detect_dll_sideloading(events, agent))

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
    lines = ["Code Signing Bypass Detection", "=" * 40, ""]
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
