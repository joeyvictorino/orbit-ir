"""DNS tunneling detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "dns_exfiltration": [
        "dns tunneling", "dns exfiltration", "dns covert channel",
        "dns data exfil", "encoded dns query", "base64 dns",
        "hex encoded subdomain", "long subdomain query",
        "dns payload encoding", "txt record exfil",
    ],
    "dns_c2": [
        "dns command and control", "dns c2 channel", "dns beacon",
        "dns callback", "periodic dns query", "dns polling",
        "dns c2 communication", "dns command channel",
        "dns control channel", "dns c2 beacon",
    ],
    "unusual_query": [
        "unusual dns query", "anomalous dns traffic", "dns query anomaly",
        "suspicious dns pattern", "dns query length anomaly",
        "excessive nxdomain", "dns entropy anomaly", "random subdomain",
        "dga domain", "domain generation algorithm",
    ],
    "protocol_abuse": [
        "dns protocol abuse", "dns amplification", "dns reflection",
        "dns rebinding", "dns hijack", "dns cache poisoning",
        "dns spoofing", "dnssec bypass", "dns zone transfer",
        "axfr query",
    ],
    "tunnel_tool": [
        "iodine tunnel", "dnscat", "dns2tcp", "dnscapy",
        "ozymandns", "heyoka dns", "tuns dns", "cobalt strike dns",
        "dns over https tunnel", "doh tunnel",
    ],
    "record_abuse": [
        "cname tunneling", "mx record exfil", "null record abuse",
        "srv record tunnel", "dns record manipulation",
        "aaaa record tunnel", "ns record abuse", "soa record abuse",
        "ptr record tunnel", "txt record misuse",
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
        "DNS Tunneling Detection Report",
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
