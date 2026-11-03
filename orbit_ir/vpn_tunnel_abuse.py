"""Detect VPN tunnel abuse patterns in agent activity logs.

Identifies VPN abuse techniques: unauthorized VPN usage, split tunnel
exploitation, VPN credential theft, malicious tunnel encapsulation,
data exfiltration via VPN, and VPN-based lateral movement.
"""

import json
from collections import Counter

CATEGORIES = {
    "unauthorized_vpn": [
        "unauthorized vpn", "rogue vpn", "unapproved vpn client",
        "shadow vpn", "personal vpn detected", "vpn policy violation",
        "unsanctioned tunnel", "banned vpn service",
        "vpn software installed", "vpn app detected",
    ],
    "split_tunnel_exploit": [
        "split tunnel exploit", "split tunneling abuse",
        "split tunnel bypass", "tunnel route manipulation",
        "selective routing abuse", "split tunnel data leak",
        "dual tunnel path", "route table manipulation",
        "tunnel bypass detected", "split tunnel misconfiguration",
    ],
    "vpn_credential_theft": [
        "vpn credential theft", "vpn password stolen",
        "vpn token compromised", "vpn auth bypass",
        "vpn certificate stolen", "vpn key extraction",
        "vpn credential dump", "vpn session hijack",
        "vpn mfa bypass", "vpn credential reuse",
    ],
    "tunnel_encapsulation": [
        "tunnel encapsulation abuse", "nested tunnel detected",
        "tunnel within tunnel", "double encapsulation",
        "protocol encapsulation exploit", "gre tunnel abuse",
        "ipsec tunnel manipulation", "wireguard abuse",
        "openvpn exploit", "tunnel protocol misuse",
    ],
    "vpn_exfiltration": [
        "vpn exfiltration", "data exfil via vpn",
        "vpn data smuggling", "tunnel data theft",
        "vpn bandwidth anomaly", "large transfer via vpn",
        "bulk vpn upload", "vpn covert channel",
        "encrypted tunnel exfil", "vpn data staging",
    ],
    "vpn_pivot": [
        "vpn pivot", "vpn lateral movement",
        "tunnel pivot detected", "vpn network hop",
        "vpn bridge attack", "cross-network vpn",
        "vpn segment bypass", "tunnel-based pivot",
        "vpn access expansion", "vpn perimeter bypass",
    ],
}


def classify_event(event):
    """Classify a single event into a VPN tunnel abuse category.

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
    """Analyze events for VPN tunnel abuse indicators.

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
    lines.append("VPN Tunnel Abuse Detection Report")
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
