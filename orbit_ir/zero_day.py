"""Zero-day exploit detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "unknown_vuln_exploit": [
        "zero-day exploit", "zero day vulnerability", "0-day exploit",
        "unknown vulnerability", "unpatched exploit", "novel exploit",
        "undisclosed vulnerability", "unreported cve", "unpublished exploit",
        "previously unknown flaw",
    ],
    "exploit_chain": [
        "exploit chain", "chained exploits", "multi-stage exploit",
        "exploit sequence", "vulnerability chaining", "staged exploitation",
        "pivot exploit", "escalation chain", "linked vulnerabilities",
        "compound exploit",
    ],
    "memory_corruption": [
        "buffer overflow", "heap spray", "use after free", "double free",
        "stack smash", "rop chain", "return oriented programming",
        "memory corruption", "out of bounds write", "type confusion",
    ],
    "logic_flaw": [
        "logic flaw", "authentication bypass", "authorization bypass",
        "race condition exploit", "toctou", "business logic flaw",
        "access control bypass", "privilege boundary bypass",
        "session fixation", "insecure deserialization",
    ],
    "browser_exploit": [
        "browser exploit", "renderer exploit", "sandbox escape browser",
        "javascript engine exploit", "v8 exploit", "webkit exploit",
        "browser zero-day", "drive-by exploit", "watering hole browser",
        "browser rce",
    ],
    "kernel_exploit": [
        "kernel exploit", "kernel zero-day", "privilege escalation kernel",
        "kernel module exploit", "syscall exploit", "kernel race condition",
        "dirty pipe", "dirty cow", "kernel heap overflow",
        "namespace escape kernel",
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
        "Zero-Day Exploit Detection Report",
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
