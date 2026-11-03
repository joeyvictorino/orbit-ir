"""Web shell detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "upload": [
        "web shell upload", "shell upload", "backdoor upload",
        "malicious file upload", "php shell upload", "asp shell upload",
        "jsp shell upload", "webshell dropped", "reverse shell uploaded",
        "file upload exploit",
    ],
    "execution": [
        "web shell execution", "shell command via web", "remote code execution",
        "webshell command", "cmd execution web", "os command injection",
        "eval injection", "system call from web", "exec via webshell",
        "arbitrary command execution",
    ],
    "persistence": [
        "web shell persistence", "backdoor persistence", "hidden web shell",
        "obfuscated shell", "encoded webshell", "persistent backdoor",
        "webshell cron", "shell auto-restart", "webshell scheduled task",
        "web backdoor maintained",
    ],
    "communication": [
        "webshell callback", "shell reverse connect", "web shell beacon",
        "encrypted webshell traffic", "webshell tunnel", "covert channel web",
        "shell phone home", "webshell exfil channel", "http tunnel shell",
        "webshell proxy",
    ],
    "discovery": [
        "webshell reconnaissance", "server enumeration via shell",
        "directory listing shell", "system info via webshell",
        "network scan webshell", "credential dump webshell",
        "database access webshell", "file browsing shell",
        "process list webshell", "environment enumeration",
    ],
    "evasion": [
        "webshell obfuscation", "encoded payload web", "base64 shell",
        "polymorphic webshell", "fileless webshell", "memory-only shell",
        "webshell anti-detection", "shell signature bypass",
        "webshell encryption", "stealth webshell",
    ],
}


def classify_event(event):
    if event is None:
        return "unknown"
    if isinstance(event, dict):
        text = " ".join(str(v) for v in event.values()).lower()
    elif isinstance(event, str):
        text = event.lower()
    else:
        return "unknown"
    if not text.strip():
        return "unknown"
    for category, indicators in CATEGORIES.items():
        for indicator in indicators:
            if indicator in text:
                return category
    return "unknown"


def analyze(events):
    total = len(events)
    flagged = []
    category_counts = {}

    for i, event in enumerate(events):
        cat = classify_event(event)
        if cat != "unknown":
            flagged.append({"index": i, "category": cat, "event": event})
            category_counts[cat] = category_counts.get(cat, 0) + 1

    flagged_count = len(flagged)
    if flagged_count > 10:
        severity = "critical"
    elif flagged_count > 5:
        severity = "high"
    elif flagged_count > 0:
        severity = "medium"
    else:
        severity = "none"

    return {
        "total_events": total,
        "flagged_count": flagged_count,
        "flagged_events": flagged,
        "category_counts": category_counts,
        "severity": severity,
        "detection_rate": flagged_count / total if total > 0 else 0.0,
    }


def format_report(result):
    lines = [
        "Web Shell Detection Report",
        "=" * 40,
        "",
        f"  Total events:      {result['total_events']}",
        f"  Flagged:           {result['flagged_count']}",
        f"  Severity:          {result['severity']}",
        f"  Detection rate:    {result['detection_rate']:.1%}",
        "",
    ]
    if result["category_counts"]:
        lines.append("  Categories:")
        for cat, count in sorted(result["category_counts"].items()):
            lines.append(f"    {cat:30s} {count}")
        lines.append("")

    shown = result["flagged_events"][:10]
    if shown:
        lines.append("  Flagged events:")
        for entry in shown:
            evt = str(entry["event"])[:80]
            lines.append(f"    [{entry['index']}] {entry['category']:20s} {evt}")
    if result["flagged_count"] > 10:
        lines.append(f"    ... and {result['flagged_count'] - 10} more")
    lines.append("")
    return "\n".join(lines)


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "events" in data:
            return data["events"]
        return [data]
    return [data]
