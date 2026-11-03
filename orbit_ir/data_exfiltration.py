"""Data exfiltration technique detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "network_exfil": [
        "data exfiltration network", "outbound data transfer",
        "large upload detected", "unusual egress traffic",
        "exfil over http", "exfil over https", "covert channel transfer",
        "data smuggling network", "bandwidth anomaly outbound",
        "suspicious outbound connection",
    ],
    "cloud_storage_exfil": [
        "upload to cloud storage", "s3 bucket upload unauthorized",
        "google drive exfil", "dropbox upload suspicious",
        "onedrive mass upload", "cloud sync exfiltration",
        "blob storage upload", "unauthorized cloud transfer",
        "mega upload exfil", "file sharing service abuse",
    ],
    "email_exfil": [
        "email exfiltration", "attachment mass send",
        "large email attachment", "email data leak",
        "forwarding rule exfil", "auto-forward sensitive",
        "bcc exfiltration", "email bulk send suspicious",
        "smtp data exfil", "outbound email anomaly",
    ],
    "physical_exfil": [
        "usb data copy", "removable media exfil",
        "external drive copy", "physical data theft",
        "usb mass storage write", "cd burn sensitive data",
        "bluetooth file transfer", "mtp device copy",
        "removable storage write", "portable drive suspicious",
    ],
    "steganography_exfil": [
        "steganography exfil", "data hidden in image",
        "covert image channel", "steganographic encoding",
        "hidden data in media", "lsb encoding detected",
        "data embedded in file", "steganographic payload",
        "image carrier exfil", "hidden channel media",
    ],
    "dns_exfil": [
        "dns exfiltration", "dns data tunnel",
        "encoded dns query", "dns covert channel",
        "high entropy subdomain", "dns txt record exfil",
        "dns query data leak", "suspicious dns payload",
        "base64 dns query", "dns beacon exfiltration",
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
        "Data Exfiltration Detection Report",
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
