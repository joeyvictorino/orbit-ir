"""Detect BGP hijack patterns in agent activity logs.

Identifies attempts to manipulate BGP routing: prefix hijacking,
route leak, AS path manipulation, BGP session hijack, route origin
validation bypass, and BGP community abuse.
"""

import json
from collections import Counter

CATEGORIES = {
    "prefix_hijack": [
        "prefix hijack", "bgp prefix theft", "ip prefix announcement",
        "unauthorized prefix", "stolen prefix", "hijacked prefix",
        "rogue prefix announcement", "prefix squatting",
        "bgp prefix spoof", "more specific prefix attack",
    ],
    "route_leak": [
        "route leak", "bgp route leak", "accidental route propagation",
        "transit leak", "peer route leak", "route redistribution leak",
        "unintended route export", "bgp policy violation leak",
        "route table leak", "prefix leak to upstream",
    ],
    "as_path_manipulation": [
        "as path manipulation", "as path prepend attack", "as path poison",
        "bgp as injection", "forged as path", "as path truncation",
        "origin as spoof", "as path loop injection",
        "bgp path attribute tamper", "as confederation abuse",
    ],
    "session_hijack": [
        "bgp session hijack", "bgp tcp hijack", "bgp peer spoof",
        "bgp authentication bypass", "bgp session reset attack",
        "bgp keepalive spoof", "bgp notification inject",
        "bgp open message spoof", "bgp md5 bypass",
        "bgp peer identity theft",
    ],
    "rov_bypass": [
        "rpki bypass", "route origin validation bypass", "roa mismatch",
        "invalid origin accepted", "rpki not found route",
        "origin validation disabled", "rpki cache poison",
        "roa manipulation", "rpki relay attack",
        "bgp rov circumvention",
    ],
    "community_abuse": [
        "bgp community abuse", "community attribute inject",
        "blackhole community spoof", "no-export bypass",
        "community tag manipulation", "bgp extended community attack",
        "large community injection", "community based filtering bypass",
        "route target hijack", "bgp community policy evasion",
    ],
}


def classify_event(event):
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
    lines = []
    lines.append("BGP Hijack Detection Report")
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
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]
