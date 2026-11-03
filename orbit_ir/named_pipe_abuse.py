"""Named pipe abuse detection for agent incident reconstruction.

Detects patterns where agents exploit named pipes and IPC mechanisms:
- pipe_impersonation: token impersonation via named pipe connections
- pipe_relay: relay attacks, NTLM relay through pipes
- pipe_privilege_escalation: escalation through pipe permissions
- pipe_covert_channel: covert communication via named pipes
- pipe_injection: injecting into processes via pipe manipulation
- pipe_enumeration: scanning and discovering named pipes for exploitation
"""

from __future__ import annotations

import json
import re
from pathlib import Path


CATEGORIES = {
    "pipe_impersonation": {
        "patterns": [
            r"(?i)(impersonate|steal)\w*\s+(named\s+pipe|pipe\s+token|client\s+token)",
            r"(?i)(impersonatenamedpipeclient|impersonateloggedonuser)\w*",
            r"(?i)(pipe)\s+(impersonat|token\s+theft|identity\s+steal)\w*",
            r"(?i)(potato|juicy|rotten|sweet|god)\s*(potato)?\s*(exploit|attack|escalat)\w*",
        ],
        "severity": "critical",
        "description": "Token impersonation via named pipe connections",
    },
    "pipe_relay": {
        "patterns": [
            r"(?i)(ntlm|kerberos)\s+(relay|forward|redirect)\w*\s*(via|through|over)\s*(pipe|ipc)\w*",
            r"(?i)(pipe|ipc)\s+(relay|man.in.the.middle|mitm|intercept)\w*",
            r"(?i)(printerbug|spoolss|petitpotam)\w*\s*(relay|coerce|trigger)\w*",
            r"(?i)(auth|credential)\s+(relay|coerce|forward)\w*\s*(named\s+pipe|pipe)\w*",
        ],
        "severity": "critical",
        "description": "Relay attacks, NTLM relay through pipes",
    },
    "pipe_privilege_escalation": {
        "patterns": [
            r"(?i)(pipe)\s+(privilege|privesc|escalat|elevat)\w*",
            r"(?i)(named\s+pipe)\s+(dacl|permission|acl)\s*(bypass|abuse|weak|exploit)\w*",
            r"(?i)(create|open)\w*\s+(pipe|ipc)\s+(system|admin|elevated|root)\w*",
            r"(?i)(service|svchost|lsass|winlogon)\s+(pipe|ipc)\s+(connect|access|exploit)\w*",
        ],
        "severity": "critical",
        "description": "Escalation through pipe permissions",
    },
    "pipe_covert_channel": {
        "patterns": [
            r"(?i)(covert|hidden|stealth)\s+(pipe|channel|ipc)\s+(communi|transfer|exfil)\w*",
            r"(?i)(named\s+pipe)\s+(tunnel|covert|backdoor|c2|command.and.control)\w*",
            r"(?i)(pipe)\s+(data\s+exfil|secret\s+transfer|steganograph)\w*",
            r"(?i)(beacon|implant|agent)\s+(communicate|connect|callback)\w*\s*(pipe|ipc)\w*",
        ],
        "severity": "high",
        "description": "Covert communication via named pipes",
    },
    "pipe_injection": {
        "patterns": [
            r"(?i)(inject|implant|payload)\w*\s*(via|through|into)\s*(named\s+pipe|pipe|ipc)\w*",
            r"(?i)(pipe)\s+(inject|implant|shellcode|payload)\w*",
            r"(?i)(write|send)\w*\s+(malicious|exploit|shellcode)\w*\s*(to|via)\s*(pipe|ipc)\w*",
            r"(?i)(transactnamedpipe|callnamedpipe)\w*\s*(inject|exploit|payload)\w*",
        ],
        "severity": "high",
        "description": "Injecting into processes via pipe manipulation",
    },
    "pipe_enumeration": {
        "patterns": [
            r"(?i)(enum|scan|discover|list)\w*\s+(named\s+pipe|pipe|ipc)\w*",
            r"(?i)(pipelist|get.childitem|dir)\w*\s*[\\\/]+pipe\w*",
            r"(?i)(named\s+pipe)\s+(enum|scan|discover|fingerprint|recon)\w*",
            r"(?i)(accesschk|icacls|getacl)\w*\s*(pipe|ipc)\w*",
        ],
        "severity": "medium",
        "description": "Scanning and discovering named pipes for exploitation",
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
        summary += "; no named pipe abuse detected"
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
        "Named Pipe Abuse Analysis",
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
