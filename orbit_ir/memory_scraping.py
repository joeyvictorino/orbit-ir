"""Memory scraping detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "ram_scraping": [
        "ram scraping", "memory scraping", "memory dump attack",
        "process memory read", "memory harvest", "ram dump",
        "physical memory read", "memory extraction",
        "volatile memory attack", "live memory capture",
    ],
    "credential_dump": [
        "credential dump", "lsass dump", "mimikatz", "password dump",
        "credential extraction", "hash dump", "sam dump",
        "ntds dit extract", "kerberoast", "golden ticket extract",
    ],
    "heap_spray": [
        "heap spray", "heap manipulation", "heap overflow exploit",
        "heap feng shui", "use after free", "double free exploit",
        "heap grooming", "heap corruption attack",
        "memory corruption exploit", "heap buffer overflow",
    ],
    "cold_boot": [
        "cold boot attack", "dram remanence", "memory freeze",
        "cold boot exploit", "ram freeze attack", "cryogenic attack",
        "physical memory freeze", "ddr remanence",
        "memory persistence attack", "cold boot key extract",
    ],
    "side_channel_mem": [
        "spectre", "meltdown", "rowhammer", "cache timing attack",
        "tlb side channel", "microarchitectural attack", "cache flush attack",
        "speculative execution", "transient execution attack",
        "branch prediction attack",
    ],
    "process_hollowing": [
        "process hollowing", "process replacement", "runpe",
        "hollow process injection", "process doppelganging",
        "unmapping process", "section replacement",
        "pe image overwrite", "process herpaderping",
        "ghost process injection",
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
        "Memory Scraping Detection Report",
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
