"""Wi-Fi attack detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "evil_twin": [
        "evil twin", "rogue access point", "rogue ap", "fake hotspot",
        "honeypot ap", "spoofed ssid", "cloned access point", "twin ap",
        "fake wifi", "impersonating ap",
    ],
    "deauth_attack": [
        "deauthentication attack", "deauth flood", "deauth frame",
        "disassociation attack", "disassociation flood", "802.11 deauth",
        "wifi deauth", "deauth packet", "client deauthentication", "forced disconnect",
    ],
    "wpa_crack": [
        "wpa crack", "wpa2 crack", "handshake capture", "pmkid attack",
        "dictionary attack wifi", "brute force wpa", "wps pin attack",
        "wifi password crack", "psk brute force",
    ],
    "krack_attack": [
        "krack", "key reinstallation attack", "krack exploit",
        "wpa2 key reinstall", "nonce reuse", "krack vulnerability",
        "four-way handshake attack", "group key reinstall",
        "pairwise key reinstall", "krack mitm",
    ],
    "karma_attack": [
        "karma attack", "probe response spoofing", "preferred network attack",
        "auto-connect exploit", "known network spoof", "pnl attack",
        "probe request sniff", "automatic association exploit",
        "wifi karma", "directed probe response",
    ],
    "packet_injection": [
        "packet injection", "frame injection", "wifi injection",
        "aircrack injection", "monitor mode inject", "raw frame injection",
        "802.11 injection", "wireless packet forge", "crafted beacon",
        "inject deauth frame",
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
        "Wi-Fi Attack Detection Report",
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
