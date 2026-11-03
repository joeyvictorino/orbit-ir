"""Detect cryptocurrency mining patterns in agent activity logs.

Identifies crypto mining techniques: unauthorized miners, resource hijacking,
pool connections, wallet injection, browser-based mining, and GPU abuse.
"""

import json
from collections import Counter

CATEGORIES = {
    "unauthorized_miner": [
        "unauthorized miner", "rogue miner detected", "cryptominer installed",
        "mining binary found", "xmrig detected", "coinminer process",
        "hidden miner", "miner executable", "mining daemon started",
        "crypto mining software",
    ],
    "resource_hijack": [
        "resource hijack", "cpu spike mining", "high cpu utilization mining",
        "resource abuse mining", "compute theft", "cpu 100% unexplained",
        "processing power stolen", "resource exhaustion mining",
        "throttled by miner", "compute resource hijack",
    ],
    "pool_connection": [
        "pool connection", "mining pool connect", "stratum protocol",
        "pool.minexmr", "mining pool traffic", "stratum+tcp",
        "hashrate submitted", "share accepted", "pool authentication",
        "mining proxy connection",
    ],
    "wallet_injection": [
        "wallet injection", "wallet address replaced", "crypto address swap",
        "clipboard hijack wallet", "wallet address modified",
        "transaction redirect", "payment address changed",
        "crypto address inject", "wallet substitution", "address clipper",
    ],
    "browser_mining": [
        "browser mining", "coinhive detected", "javascript miner",
        "webassembly miner", "browser crypto mining", "in-browser miner",
        "cryptojacking script", "web miner loaded",
        "browser cpu spike mining", "service worker miner",
    ],
    "gpu_abuse": [
        "gpu abuse", "gpu mining detected", "cuda miner",
        "opencl mining", "gpu compute hijack", "graphics card mining",
        "gpu utilization mining", "unauthorized gpu workload",
        "gpu resource theft", "gpu hashrate spike",
    ],
}


def classify_event(event):
    """Classify a single event into a crypto mining category.

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
    """Analyze events for cryptocurrency mining indicators.

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

    severity = "critical" if len(flagged) > 10 else "high" if len(flagged) > 5 else "medium" if len(flagged) > 0 else "none"

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
    lines.append("Cryptocurrency Mining Detection Report")
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
