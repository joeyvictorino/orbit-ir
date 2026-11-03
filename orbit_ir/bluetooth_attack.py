"""Detect Bluetooth-based attack patterns in agent activity logs.

Identifies Bluetooth attack techniques: BlueBorne exploitation, Bluetooth
sniffing and eavesdropping, BlueJacking/BlueSnarfing, Bluetooth relay attacks,
BLE beacon spoofing, and Bluetooth protocol fuzzing.
"""

import json
from collections import Counter

CATEGORIES = {
    "blueborne_exploit": [
        "blueborne", "bluetooth rce", "l2cap overflow", "bnep exploit",
        "bluetooth stack overflow", "sdp vulnerability", "bluetooth remote code",
        "bluetooth heap overflow", "bt stack crash", "bluetooth kernel exploit",
    ],
    "bluetooth_sniffing": [
        "bluetooth sniff", "bt eavesdrop", "bluetooth capture",
        "ubertooth", "bt packet capture", "bluetooth intercept",
        "bluetooth monitor mode", "hci dump", "bluetooth traffic capture",
        "bluetooth passive scan",
    ],
    "bluejack_bluesnarf": [
        "bluejacking", "bluesnarfing", "obex push unsolicited",
        "bluetooth file steal", "bluetooth contact extract", "obex ftp attack",
        "bluetooth message inject", "bt phonebook dump", "bluetooth calendar steal",
        "bluesnarf opp",
    ],
    "bluetooth_relay": [
        "bluetooth relay", "bt mitm", "bluetooth man in the middle",
        "bluetooth proxy", "bluetooth bridge attack", "bt signal relay",
        "bluetooth amplification relay", "gatt relay", "bt tap forward",
        "bluetooth repeater attack",
    ],
    "ble_beacon_spoof": [
        "ble beacon spoof", "ibeacon fake", "eddystone spoof",
        "ble advertise malicious", "bluetooth low energy spoof",
        "beacon clone", "ble impersonate", "fake ble device",
        "ble uuid spoof", "proximity beacon forge",
    ],
    "bluetooth_fuzzing": [
        "bluetooth fuzz", "bt protocol fuzz", "l2cap fuzz",
        "rfcomm fuzz", "sdp fuzz", "bluetooth crash test",
        "bt malformed packet", "bluetooth stress test", "hci fuzz",
        "ble gatt fuzz",
    ],
}


def classify_event(event):
    """Classify a single event into a Bluetooth attack category.

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
    """Analyze events for Bluetooth attack indicators.

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
    lines.append("Bluetooth Attack Detection Report")
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
