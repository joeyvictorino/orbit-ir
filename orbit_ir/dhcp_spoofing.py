"""Detect DHCP spoofing patterns in agent activity logs.

Identifies attempts to manipulate DHCP services: rogue DHCP servers,
DHCP starvation attacks, spoofed DHCP offers, DHCP relay abuse,
option injection, and lease manipulation.
"""

import json
from collections import Counter

CATEGORIES = {
    "rogue_server": [
        "rogue dhcp", "unauthorized dhcp server", "fake dhcp server",
        "dhcp server spoof", "illegitimate dhcp", "phantom dhcp",
        "unregistered dhcp server", "dhcp rogue detection",
        "competing dhcp server", "dhcp server impersonation",
    ],
    "starvation": [
        "dhcp starvation", "address pool exhaustion", "dhcp flood",
        "lease exhaustion", "ip pool depletion", "dhcp dos",
        "address space depletion", "dhcp resource exhaustion",
        "pool starvation attack", "lease table overflow",
    ],
    "spoofed_offer": [
        "spoofed dhcp offer", "fake dhcp response", "dhcp offer spoof",
        "forged dhcp ack", "counterfeit lease offer", "bogus dhcp reply",
        "dhcp response injection", "altered dhcp offer",
        "tampered dhcp response", "malicious dhcp offer",
    ],
    "relay_abuse": [
        "dhcp relay abuse", "relay agent spoof", "option 82 injection",
        "dhcp relay hijack", "giaddr manipulation", "relay forward spoof",
        "dhcp helper abuse", "relay circuit injection",
        "agent relay manipulation", "dhcp proxy abuse",
    ],
    "option_injection": [
        "dhcp option injection", "option 3 manipulation", "gateway inject",
        "dns server inject", "option 6 manipulation", "wpad injection",
        "dhcp option 252", "tftp server inject", "ntp server inject",
        "dhcp option tamper",
    ],
    "lease_manipulation": [
        "lease manipulation", "lease time tamper", "short lease attack",
        "lease renewal hijack", "dhcp rebind attack", "lease expiry forge",
        "forced lease renewal", "lease preemption",
        "dhcp release spoof", "lease table poison",
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
    lines.append("DHCP Spoofing Detection Report")
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
