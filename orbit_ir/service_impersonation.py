"""Detect service impersonation patterns in agent activity logs.

Identifies attempts to impersonate legitimate services: fake API endpoints,
spoofed service identities, man-in-the-middle service proxies, service
name collision, certificate impersonation, and DNS-based service spoofing.
"""

import json
from collections import Counter

CATEGORIES = {
    "fake_api": [
        "fake api", "spoofed endpoint", "rogue api server", "mock service",
        "shadow api", "unauthorized api", "api impersonation",
        "counterfeit endpoint", "phishing api", "cloned api",
    ],
    "identity_spoof": [
        "identity spoof", "service impersonation", "spoofed identity",
        "fake service name", "service masquerade", "impersonated service",
        "forged service header", "service identity theft",
        "spoofed service token", "fake service certificate",
    ],
    "mitm_proxy": [
        "mitm proxy", "man in the middle", "intercepting proxy",
        "transparent proxy inject", "ssl strip", "tls intercept",
        "proxy injection", "traffic interception", "relay attack",
        "service proxy hijack",
    ],
    "name_collision": [
        "name collision", "service name conflict", "duplicate service",
        "namespace squatting", "service shadowing", "name hijack",
        "registry poisoning", "service discovery spoof",
        "dns service collision", "container name spoof",
    ],
    "cert_impersonation": [
        "cert impersonation", "fake certificate", "self-signed spoof",
        "certificate forgery", "ca impersonation", "ssl cert clone",
        "tls cert spoof", "certificate pinning bypass",
        "fraudulent certificate", "rogue ca",
    ],
    "dns_spoof": [
        "dns spoof", "dns hijack", "dns poisoning service",
        "service dns redirect", "dns rebinding", "fake dns record",
        "dns cache poison", "service resolution spoof",
        "rogue dns entry", "dns takeover",
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
    lines.append("Service Impersonation Detection Report")
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
