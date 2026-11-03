"""Registry manipulation detection for agent incident reconstruction.

Detects patterns where agents tamper with Windows registry keys:
- persistence_registry: Run keys, services, scheduled tasks via registry
- security_bypass: disabling Defender, UAC, firewall via registry
- credential_access: SAM/SECURITY/SYSTEM hive access or export
- config_tampering: modifying system policies, network settings
- evasion_registry: clearing audit logs, hiding files via registry
- com_hijack: COM object hijacking, CLSID redirection
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


CATEGORIES = {
    "persistence_registry": {
        "patterns": [
            r"(?i)(hklm|hkcu)[\\\/].*?(run|runonce|startup)\b",
            r"(?i)reg\s+(add|set)\s+.*?(currentversion[\\\/]run|services)\b",
            r"(?i)(winlogon|userinit|shell|load)\s*=\s*\S+",
            r"(?i)schtasks.*?\/create.*?\/reg",
            r"(?i)(registry|reg)\s+(persist|autostart|boot\s+entry)",
        ],
        "severity": "critical",
        "description": "Persistence via Run keys, services, scheduled tasks",
    },
    "security_bypass": {
        "patterns": [
            r"(?i)(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)\s*=\s*1",
            r"(?i)(enablelua|consentpromptbehavioradmin)\s*=\s*0",
            r"(?i)(enablefirewall|donotallowexceptions)\s*=\s*0",
            r"(?i)reg\s+(add|set)\s+.*?(defender|firewall|uac).*?(disable|0)",
            r"(?i)(tamper\s+protect|security\s+center)\s+(bypass|disable|override)",
        ],
        "severity": "critical",
        "description": "Disabling Defender, UAC, firewall via registry",
    },
    "credential_access": {
        "patterns": [
            r"(?i)(sam|security|system)\s+(hive|dump|export|copy|save)\w*",
            r"(?i)reg\s+save\s+hklm[\\\/](sam|security|system)\b",
            r"(?i)(lsa|lsass|ntds)\s+(secrets?|dump|extract)\w*",
            r"(?i)(cached\s+credentials?|credential\s+manager)\s+(dump|read|export|access)\w*",
        ],
        "severity": "critical",
        "description": "SAM/SECURITY/SYSTEM hive access or export",
    },
    "config_tampering": {
        "patterns": [
            r"(?i)reg\s+(add|set|delete)\s+.*?(policies|network|tcpip|dns)\b",
            r"(?i)(group\s+policy|gpo)\s+(modify|tamper|inject|update)\w*",
            r"(?i)(proxy|internet\s+settings?|winhttp)\s+(set|modify|redirect)\w*",
            r"(?i)(hosts?\s+file|dns\s+server)\s+(modify|redirect|poison)\w*",
        ],
        "severity": "high",
        "description": "Modifying system policies, network settings",
    },
    "evasion_registry": {
        "patterns": [
            r"(?i)(clear|delete|wipe|purge)\s+(event\s+log|audit\s+log|security\s+log)\w*",
            r"(?i)reg\s+delete\s+.*?(eventlog|audit|recent)\b",
            r"(?i)(hidden|superhidden|nosecuritytab)\s*=\s*[12]",
            r"(?i)(prefetch|mru|recent|shellbag)\s+(clear|delete|wipe)\w*",
        ],
        "severity": "high",
        "description": "Clearing audit logs, hiding files via registry",
    },
    "com_hijack": {
        "patterns": [
            r"(?i)(clsid|progid|typelib)[\\\/]\{[a-f0-9\-]+\}",
            r"(?i)(inprocserver32|localserver32)\s*=\s*\S+",
            r"(?i)(com|dcom)\s+(hijack|redirect|spoof|replace)\w*",
            r"(?i)(scrobj|scriptlet|sct)\s+(register|load|execute)\w*",
        ],
        "severity": "medium",
        "description": "COM object hijacking, CLSID redirection",
    },
}


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


def classify_event(event: dict) -> list[dict]:
    text = " ".join(str(v) for v in event.values())
    results = []

    for cat, info in CATEGORIES.items():
        match_count = 0
        matched_patterns = []
        for pat in _get_patterns(cat):
            m = pat.search(text)
            if m:
                match_count += 1
                matched_patterns.append(m.group(0)[:80])
        if match_count > 0:
            confidence = min(1.0, round(match_count * 0.3, 2))
            results.append({
                "category": cat,
                "details": "; ".join(matched_patterns[:3]),
                "severity": info["severity"],
                "confidence": confidence,
            })

    return results


def analyze(events: list[dict]) -> dict:
    total = len(events)
    flagged = 0
    cat_data: dict[str, dict] = {}
    for cat, info in CATEGORIES.items():
        cat_data[cat] = {
            "count": 0,
            "severity": info["severity"],
            "events": [],
        }

    for ev in events:
        matches = classify_event(ev)
        if matches:
            flagged += 1
        for m in matches:
            c = m["category"]
            cat_data[c]["count"] += 1
            if len(cat_data[c]["events"]) < 10:
                cat_data[c]["events"].append({
                    "event": {k: v for k, v in ev.items() if k != "raw"},
                    "details": m["details"],
                    "confidence": m["confidence"],
                })

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    weighted = sum(
        d["count"] * severity_weight.get(d["severity"], 0.3)
        for d in cat_data.values()
    )
    risk = min(1.0, round(weighted / max(total, 1), 2))

    summary = f"{flagged} of {total} events flagged"
    if flagged == 0:
        summary += "; no registry manipulation detected"
    else:
        top = sorted(cat_data.items(), key=lambda x: x[1]["count"], reverse=True)
        top_cats = [c for c, d in top if d["count"] > 0][:3]
        summary += f"; top categories: {', '.join(top_cats)}"

    return {
        "total_events": total,
        "flagged": flagged,
        "categories": cat_data,
        "risk_score": risk,
        "summary": summary,
    }


def format_report(analysis: dict) -> str:
    lines = [
        "Registry Manipulation Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Flagged events: {analysis.get('flagged', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f}",
        "",
    ]

    for cat, data in analysis.get("categories", {}).items():
        if data["count"] > 0:
            lines.append(
                f"  {cat:<30s}  {data['count']:>3d} events  "
                f"severity={data['severity']}"
            )

    lines.append("")
    lines.append(f"Summary: {analysis.get('summary', '')}")
    lines.append("")
    return "\n".join(lines)


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file():
        if p.suffix != ".json":
            return events
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
        return events
    for f in sorted(p.iterdir()):
        if f.suffix == ".json":
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except (json.JSONDecodeError, OSError):
                pass
    return events
