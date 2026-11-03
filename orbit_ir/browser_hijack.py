"""Detect browser hijacking patterns in agent activity logs.

Identifies browser hijacking techniques: extension injection, homepage
tampering, search engine redirection, cookie theft, session hijacking,
and browser credential harvesting.
"""

import json
from collections import Counter

CATEGORIES = {
    "extension_injection": [
        "extension injection", "malicious extension", "rogue extension",
        "browser addon inject", "extension sideload", "forced extension",
        "extension policy override", "stealth extension install",
        "extension permissions abuse", "hidden extension loaded",
    ],
    "homepage_tamper": [
        "homepage tamper", "homepage changed", "default page hijack",
        "new tab override", "startup page modified", "browser home redirect",
        "homepage policy violation", "landing page altered",
        "browser settings changed", "forced homepage",
    ],
    "search_redirect": [
        "search redirect", "search engine hijack", "search query intercept",
        "default search changed", "search results tampered",
        "search proxy injection", "query parameter inject",
        "search affiliate fraud", "serp manipulation", "search dns redirect",
    ],
    "cookie_theft": [
        "cookie theft", "cookie exfiltration", "session cookie stolen",
        "cookie jar access", "cookie database read", "browser cookie dump",
        "cookie replay attack", "httponly cookie bypass",
        "cookie decrypt attempt", "cross-site cookie leak",
    ],
    "session_hijack": [
        "session hijack", "session token stolen", "session fixation",
        "session replay", "session cloning", "tab napping",
        "browser session takeover", "auth session theft",
        "session persistence abuse", "session id intercept",
    ],
    "credential_harvest": [
        "credential harvest", "browser password dump", "saved password theft",
        "autofill data stolen", "form data intercept", "login keylog",
        "password store access", "credential database read",
        "browser vault extract", "password manager exploit",
    ],
}


def classify_event(event):
    """Classify a single event into a browser hijack category.

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
    """Analyze events for browser hijacking indicators.

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
    lines.append("Browser Hijack Detection Report")
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
