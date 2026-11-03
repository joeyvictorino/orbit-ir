"""Network scan detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "port_scan": [
        "port scan", "port scanning", "syn scan", "tcp scan",
        "udp scan", "stealth scan", "xmas scan", "fin scan",
        "null scan", "connect scan",
    ],
    "service_enumeration": [
        "service enumeration", "service detection", "banner grabbing",
        "version detection", "service fingerprint", "service probe",
        "application fingerprint", "protocol detection",
        "service identification", "version scan",
    ],
    "arp_scan": [
        "arp scan", "arp discovery", "arp sweep", "arp poisoning",
        "arp spoofing", "arp cache", "arp request flood",
        "arp table", "gratuitous arp", "arp probe",
    ],
    "icmp_sweep": [
        "icmp sweep", "ping sweep", "icmp scan", "ping scan",
        "icmp echo", "icmp flood", "ping flood", "icmp discovery",
        "host discovery ping", "icmp probe",
    ],
    "traceroute": [
        "traceroute", "tracert", "route tracing", "path discovery",
        "network path", "hop enumeration", "route mapping",
        "ttl probe", "path analysis", "network topology trace",
    ],
    "dns_enumeration": [
        "dns enumeration", "dns scan", "zone transfer", "dns brute",
        "subdomain enumeration", "dns recon", "reverse dns",
        "dns lookup", "dns discovery", "domain enumeration",
    ],
    "smb_enumeration": [
        "smb enumeration", "smb scan", "netbios scan", "smb share",
        "smb brute", "cifs scan", "windows share enumeration",
        "smb relay", "smb signing", "netbios enumeration",
    ],
    "snmp_scan": [
        "snmp scan", "snmp enumeration", "snmp walk", "snmp sweep",
        "community string", "snmp brute", "snmp discovery",
        "snmp query", "mib walk", "snmp probe",
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
        "Network Scan Detection Report",
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
