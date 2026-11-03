"""Detect RF/wireless interference and jamming patterns in agent activity logs.

Identifies radio frequency attack techniques: WiFi deauthentication/jamming,
GPS spoofing and jamming, RFID cloning and skimming, cellular signal
manipulation, SDR-based attacks, and broadband RF jamming.
"""

import json
from collections import Counter

CATEGORIES = {
    "wifi_deauth_jam": [
        "wifi deauth", "deauthentication attack", "wifi jamming",
        "802.11 deauth", "wireless dos", "beacon flood",
        "wifi disassociate", "aireplay deauth", "wifi channel jam",
        "wlan interference",
    ],
    "gps_spoof_jam": [
        "gps spoof", "gps jamming", "gnss interference",
        "gps signal fake", "location spoof", "gps replay attack",
        "navigation signal tamper", "gps meaconing", "satellite signal jam",
        "position falsification",
    ],
    "rfid_clone_skim": [
        "rfid clone", "rfid skim", "nfc relay attack",
        "rfid replay", "contactless skim", "proxmark",
        "rfid emulate", "badge clone", "mifare crack",
        "rfid intercept",
    ],
    "cellular_manipulation": [
        "imsi catcher", "stingray device", "cell tower spoof",
        "baseband exploit", "ss7 intercept", "cellular intercept",
        "fake base station", "lte redirection", "gsm intercept",
        "mobile signal jam",
    ],
    "sdr_attack": [
        "sdr attack", "software defined radio", "hackrf",
        "rtl-sdr malicious", "sdr replay", "radio signal capture",
        "sdr transmit unauthorized", "rf signal clone", "sdr intercept",
        "radio frequency replay",
    ],
    "broadband_rf_jam": [
        "broadband jammer", "rf jammer", "electromagnetic pulse",
        "emp attack", "wideband interference", "spectrum denial",
        "radio blackout", "frequency sweep jam", "noise generator attack",
        "full spectrum jam",
    ],
}


def classify_event(event):
    """Classify a single event into an RF interference category.

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
    """Analyze events for RF interference and jamming indicators.

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
    lines.append("RF Interference Detection Report")
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
