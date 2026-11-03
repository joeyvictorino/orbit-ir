"""Watering hole attack detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "compromised_website": [
        "compromised website", "watering hole", "strategic web compromise",
        "trusted site exploit", "legitimate site compromised",
        "website defacement", "web server backdoor", "site injection",
        "compromised web server", "trusted domain exploit",
    ],
    "drive_by_download": [
        "drive-by download", "drive by download", "silent download",
        "automatic download", "exploit kit download", "browser download exploit",
        "unintended download", "stealth download", "background download",
        "hidden download payload",
    ],
    "iframe_injection": [
        "iframe injection", "hidden iframe", "malicious iframe",
        "injected iframe", "invisible iframe", "iframe redirect",
        "iframe exploit", "cross-frame scripting", "iframe overlay",
        "nested iframe attack",
    ],
    "malvertising": [
        "malvertising", "malicious advertisement", "ad exploit",
        "compromised ad network", "malicious ad redirect",
        "ad-based exploit", "poisoned advertisement", "ad injection",
        "rogue ad server", "advertising malware",
    ],
    "browser_exploit": [
        "browser exploit", "browser vulnerability", "zero-day browser",
        "browser rce", "javascript exploit", "webassembly exploit",
        "browser memory corruption", "use-after-free browser",
        "browser sandbox escape", "renderer exploit",
    ],
    "redirect_chain": [
        "redirect chain", "url redirect exploit", "multi-hop redirect",
        "malicious redirect", "302 redirect attack", "meta refresh attack",
        "javascript redirect chain", "traffic distribution system",
        "redirect to exploit kit", "cloaked redirect",
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
        "Watering Hole Attack Detection Report",
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
