"""Detect SSRF (Server-Side Request Forgery) attack indicators in agent behavior logs.

Identifies techniques for exploiting server-side request capabilities:
internal network probing, cloud metadata access, localhost access,
URL scheme abuse, DNS rebinding, and redirect chain exploitation.
"""

import json
from collections import Counter

CATEGORIES = {
    "internal_network_probe": [
        "internal ip scan", "private range request", "10.0.0 access",
        "172.16 access", "192.168 access", "intranet endpoint probe",
        "internal service discovery", "port scan via request",
        "subnet enumeration", "internal host resolve",
    ],
    "cloud_metadata_access": [
        "169.254.169.254", "metadata api request", "imds endpoint",
        "cloud metadata fetch", "instance identity document",
        "iam credentials via metadata", "gcp metadata server",
        "azure imds access", "aws metadata token", "link-local metadata",
    ],
    "localhost_access": [
        "localhost request", "127.0.0.1 access", "loopback connection",
        "0.0.0.0 request", "local service access", "::1 ipv6 local",
        "localhost admin panel", "local api access", "self request loop",
        "local socket connect",
    ],
    "url_scheme_abuse": [
        "file:// scheme", "gopher:// request", "dict:// protocol",
        "ftp:// internal", "ldap:// injection", "tftp:// access",
        "jar:// scheme", "netdoc:// access", "php:// filter",
        "data:// scheme ssrf",
    ],
    "dns_rebinding": [
        "dns rebinding", "dns rebind attack", "ttl manipulation",
        "dns cache poison ssrf", "domain rebind", "time-of-check bypass",
        "dns resolution race", "rebinding payload", "dual-answer dns",
        "ip rotation attack",
    ],
    "redirect_chain": [
        "redirect chain ssrf", "open redirect exploit", "302 redirect abuse",
        "redirect to internal", "url redirect bypass", "header redirect ssrf",
        "location header manipulate", "redirect loop exploit",
        "chained redirect attack", "redirect whitelist bypass",
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
    lines.append("SSRF Attack Detection Report")
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
