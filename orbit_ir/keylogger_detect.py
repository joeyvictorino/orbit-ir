"""Keylogger behavior detection for agent incident reconstruction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Detection:
    category: str
    severity: str
    agent: str
    description: str
    evidence: str
    timestamp: str = ""


INPUT_CAPTURE_PATTERNS: set[str] = {
    "getasynckeystate",
    "setwindowshookex",
    "rawinputdevice",
    "registerrawinputdevices",
    "keybd_event",
    "sendinput",
    "getkeystate",
    "getkeyboardstate",
    "xinput",
    "xgrabkeyboard",
    "xrecord",
    "/dev/input/event",
    "evdev",
    "ioctl",
    "cgdisplaystream",
    "cgeventtapcreate",
    "iohidmanager",
}

EXFIL_PATTERNS: set[str] = {
    "smtp",
    "ftp_upload",
    "http_post",
    "dns_exfil",
    "webhook",
    "pastebin",
    "telegram",
    "discord_webhook",
}

LOG_FILE_PATTERNS: set[str] = {
    "keylog",
    "keystrokes",
    "typed_keys",
    "captured_keys",
    "input_log",
    "key_capture",
    "keystroke_log",
}

CLIPBOARD_PATTERNS: set[str] = {
    "getclipboarddata",
    "openclipboard",
    "xclip",
    "xsel",
    "pbpaste",
    "wl-paste",
    "clipboard_monitor",
}

SCREENSHOT_PATTERNS: set[str] = {
    "bitblt",
    "printwindow",
    "capturescreenshot",
    "xgetimage",
    "screencapture",
    "scrot",
    "import -window",
    "cgwindowlistcreateimage",
}


def _get_action(event: dict[str, Any]) -> str:
    return str(event.get("action", "")).lower()


def _get_target(event: dict[str, Any]) -> str:
    return str(event.get("target", "")).lower()


def _get_detail(event: dict[str, Any]) -> str:
    return str(event.get("detail", "")).lower()


def _get_agent(event: dict[str, Any]) -> str:
    return str(event.get("agent", "unknown"))


def _get_ts(event: dict[str, Any]) -> str:
    return str(event.get("timestamp", ""))


def _matches_any(text: str, patterns: set[str]) -> str | None:
    low = text.lower()
    for p in sorted(patterns):
        if p in low:
            return p
    return None


def _detect_input_hooking(events: list[dict[str, Any]]) -> list[Detection]:
    results: list[Detection] = []
    for ev in events:
        combined = f"{_get_action(ev)} {_get_target(ev)} {_get_detail(ev)}"
        match = _matches_any(combined, INPUT_CAPTURE_PATTERNS)
        if match:
            results.append(Detection(
                category="input_hooking",
                severity="critical",
                agent=_get_agent(ev),
                description=f"Input capture API detected: {match}",
                evidence=combined.strip()[:200],
                timestamp=_get_ts(ev),
            ))
    return results


def _detect_keystroke_logging(events: list[dict[str, Any]]) -> list[Detection]:
    results: list[Detection] = []
    for ev in events:
        action = _get_action(ev)
        target = _get_target(ev)
        if action in ("write", "create", "append"):
            match = _matches_any(target, LOG_FILE_PATTERNS)
            if match:
                results.append(Detection(
                    category="keystroke_logging",
                    severity="critical",
                    agent=_get_agent(ev),
                    description=f"Keystroke log file activity: {match}",
                    evidence=f"{action} -> {target}"[:200],
                    timestamp=_get_ts(ev),
                ))
    return results


def _detect_clipboard_capture(events: list[dict[str, Any]]) -> list[Detection]:
    results: list[Detection] = []
    for ev in events:
        combined = f"{_get_action(ev)} {_get_target(ev)} {_get_detail(ev)}"
        match = _matches_any(combined, CLIPBOARD_PATTERNS)
        if match:
            results.append(Detection(
                category="clipboard_capture",
                severity="high",
                agent=_get_agent(ev),
                description=f"Clipboard access detected: {match}",
                evidence=combined.strip()[:200],
                timestamp=_get_ts(ev),
            ))
    return results


def _detect_screenshot_capture(events: list[dict[str, Any]]) -> list[Detection]:
    results: list[Detection] = []
    for ev in events:
        combined = f"{_get_action(ev)} {_get_target(ev)} {_get_detail(ev)}"
        match = _matches_any(combined, SCREENSHOT_PATTERNS)
        if match:
            results.append(Detection(
                category="screenshot_capture",
                severity="high",
                agent=_get_agent(ev),
                description=f"Screen capture detected: {match}",
                evidence=combined.strip()[:200],
                timestamp=_get_ts(ev),
            ))
    return results


def _detect_exfiltration(events: list[dict[str, Any]]) -> list[Detection]:
    results: list[Detection] = []
    for ev in events:
        combined = f"{_get_action(ev)} {_get_target(ev)} {_get_detail(ev)}"
        match = _matches_any(combined, EXFIL_PATTERNS)
        if match:
            results.append(Detection(
                category="exfiltration",
                severity="critical",
                agent=_get_agent(ev),
                description=f"Data exfiltration channel detected: {match}",
                evidence=combined.strip()[:200],
                timestamp=_get_ts(ev),
            ))
    return results


def analyze_keylogger(events: list[dict[str, Any]]) -> dict[str, Any]:
    detections: list[Detection] = []
    detections.extend(_detect_input_hooking(events))
    detections.extend(_detect_keystroke_logging(events))
    detections.extend(_detect_clipboard_capture(events))
    detections.extend(_detect_screenshot_capture(events))
    detections.extend(_detect_exfiltration(events))

    by_category: dict[str, int] = {}
    agents: set[str] = set()
    for d in detections:
        by_category[d.category] = by_category.get(d.category, 0) + 1
        agents.add(d.agent)

    has_critical = any(d.severity == "critical" for d in detections)

    return {
        "detections": detections,
        "summary": {
            "total_detections": len(detections),
            "by_category": by_category,
            "agents_involved": sorted(agents),
            "overall_severity": "critical" if has_critical else ("high" if detections else "none"),
        },
    }


def format_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("Keylogger Behavior Detection")
    lines.append("=" * 50)
    s = result["summary"]
    lines.append(f"  Total detections:  {s['total_detections']}")
    lines.append(f"  Agents involved:   {', '.join(s['agents_involved']) or 'none'}")
    lines.append(f"  Overall severity:  {s['overall_severity']}")
    lines.append("")

    if s["by_category"]:
        lines.append("  By category:")
        for cat, count in sorted(s["by_category"].items()):
            lines.append(f"    {cat}: {count}")
        lines.append("")

    for d in result["detections"]:
        lines.append(f"  [{d.severity.upper()}] {d.description}")
        lines.append(f"    Agent: {d.agent}")
        if d.evidence:
            lines.append(f"    Evidence: {d.evidence}")
        if d.timestamp:
            lines.append(f"    Time: {d.timestamp}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(result: dict[str, Any]) -> str:
    serializable = {
        "detections": [
            {
                "category": d.category,
                "severity": d.severity,
                "agent": d.agent,
                "description": d.description,
                "evidence": d.evidence,
                "timestamp": d.timestamp,
            }
            for d in result["detections"]
        ],
        "summary": result["summary"],
    }
    return json.dumps(serializable, indent=2) + "\n"


def _load_events(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        if "events" in raw:
            return raw["events"]
        return [raw]
    return []
