"""Detect spear phishing attack patterns in agent activity logs.

Identifies targeted phishing techniques: personalized lures, social
engineering reconnaissance, credential harvesting pages, brand
impersonation, attachment-based payloads, and callback phishing
(vishing/smishing pretexts).
"""

import json
from collections import Counter

CATEGORIES = {
    "personalized_lure": [
        "personalized email", "targeted message", "spear phish",
        "custom lure", "tailored payload", "individual target",
        "context-aware phish", "reconnaissance-based",
        "victim-specific", "name-based lure",
    ],
    "social_recon": [
        "linkedin scrape", "social media recon", "org chart harvest",
        "employee lookup", "role identification", "reporting structure",
        "contact enumeration", "public profile harvest",
        "social engineering recon", "osint gathering",
    ],
    "credential_harvest": [
        "credential harvest page", "fake login", "phishing portal",
        "oauth phish", "token capture", "mfa bypass phish",
        "session hijack phish", "evilginx", "modlishka",
        "credential relay",
    ],
    "brand_impersonation": [
        "brand impersonation", "lookalike domain", "typosquat domain",
        "homoglyph domain", "brand spoof", "logo theft",
        "corporate template clone", "email header spoof",
        "display name spoof", "sender impersonation",
    ],
    "attachment_payload": [
        "malicious attachment", "weaponized document", "macro payload",
        "dropper document", "embedded exploit", "pdf exploit",
        "office macro", "iso attachment", "lnk payload",
        "html smuggling",
    ],
    "callback_phishing": [
        "callback phish", "vishing pretext", "smishing lure",
        "phone callback", "voicemail phish", "sms phish",
        "qr code phish", "quishing", "bazacall",
        "telephone-oriented attack",
    ],
}


def classify_event(event):
    """Classify a single event into a spear phishing category.

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
    """Analyze events for spear phishing attempt indicators.

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
    lines.append("Spear Phishing Detection Report")
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
