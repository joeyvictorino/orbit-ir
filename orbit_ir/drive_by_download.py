"""Drive-by download attack detection for agent evidence.

Identifies drive-by download techniques in agent activity: exploit kit
indicators, malvertising network abuse, browser and plugin exploitation,
silent downloads without user interaction, and obfuscated payload delivery.
"""

import json
from collections import Counter

CATEGORIES = {
    "exploit_kit": [
        "exploit kit", "angler exploit", "rig exploit", "magnitude exploit",
        "nuclear exploit", "sundown exploit", "fallout exploit",
        "spelevo exploit", "underminer exploit", "grandsoft exploit",
    ],
    "malvertising": [
        "malvertising", "malicious ad", "ad network abuse",
        "poisoned advertisement", "compromised ad server",
        "ad redirect chain", "malicious banner", "ad injection",
        "rogue ad network", "advertising exploit",
    ],
    "browser_exploit": [
        "browser exploit", "browser vulnerability", "chrome exploit",
        "firefox exploit", "edge exploit", "safari exploit",
        "webkit exploit", "v8 exploit", "use-after-free browser",
        "browser sandbox escape",
    ],
    "plugin_exploit": [
        "flash exploit", "java exploit", "silverlight exploit",
        "plugin vulnerability", "activex exploit", "pdf reader exploit",
        "adobe exploit", "java applet exploit", "browser plugin exploit",
        "shockwave exploit",
    ],
    "silent_download": [
        "silent download", "background download", "stealth download",
        "drive-by download", "hidden download", "automatic download",
        "no-click download", "invisible download", "fileless download",
        "transparent download",
    ],
    "obfuscated_payload": [
        "obfuscated payload", "encoded payload", "packed executable",
        "polymorphic payload", "encrypted dropper", "base64 payload",
        "xor encoded", "custom packer", "metamorphic payload",
        "shellcode obfuscation",
    ],
}


def classify_event(event):
    """Classify a single event into a drive-by download category.

    Returns the category name or 'unknown'.
    """
    text = ""
    if isinstance(event, dict):
        text = " ".join(str(v) for v in event.values()).lower()
    elif isinstance(event, str):
        text = event.lower()
    else:
        return "unknown"

    for category, indicators in CATEGORIES.items():
        for indicator in indicators:
            if indicator in text:
                return category
    return "unknown"


def analyze(events):
    """Analyze events for drive-by download attack indicators.

    Returns a dict with category counts, flagged events, and summary stats.
    """
    category_counts = Counter()
    flagged = []
    total = len(events)

    for i, event in enumerate(events):
        cat = classify_event(event)
        if cat != "unknown":
            category_counts[cat] += 1
            flagged.append({
                "index": i,
                "category": cat,
                "event": event,
            })

    severity = (
        "critical" if len(flagged) > 10
        else "high" if len(flagged) > 5
        else "medium" if len(flagged) > 0
        else "none"
    )

    return {
        "total_events": total,
        "flagged_count": len(flagged),
        "category_counts": dict(category_counts),
        "flagged_events": flagged,
        "severity": severity,
        "detection_rate": round(len(flagged) / total, 4) if total > 0 else 0.0,
    }


def format_report(results):
    """Format analysis results as a human-readable report."""
    lines = []
    lines.append("Drive-by Download Detection Report")
    lines.append("=" * 50)
    lines.append(f"Total events analyzed: {results['total_events']}")
    lines.append(f"Flagged events:        {results['flagged_count']}")
    lines.append(f"Detection rate:        {results['detection_rate']:.2%}")
    lines.append(f"Severity:              {results['severity']}")
    lines.append("")

    if results["category_counts"]:
        lines.append("Category Breakdown:")
        lines.append("-" * 40)
        for cat, count in sorted(results["category_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:30s} {count:>4d}")
        lines.append("")

    if results["flagged_events"]:
        lines.append("Flagged Events (first 10):")
        lines.append("-" * 40)
        for entry in results["flagged_events"][:10]:
            lines.append(f"  [{entry['index']}] {entry['category']}: {entry['event']}")
        if len(results["flagged_events"]) > 10:
            lines.append(f"  ... and {len(results['flagged_events']) - 10} more")

    return "\n".join(lines) + "\n"


def load_events(path):
    """Load events from a JSON file (list of event objects or strings)."""
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]
