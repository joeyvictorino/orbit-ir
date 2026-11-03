"""Detect CAPTCHA bypass patterns in agent activity logs.

Identifies CAPTCHA bypass techniques: automated solving, token replay
attacks, OCR-based breaking, audio CAPTCHA exploitation, behavioral
CAPTCHA spoofing, and rate flooding attacks.
"""

import json
from collections import Counter

CATEGORIES = {
    "automated_solving": [
        "automated captcha", "captcha solver", "captcha bypass bot",
        "auto-solve captcha", "captcha cracking", "machine captcha solve",
        "captcha automation", "programmatic captcha",
        "captcha farm request", "captcha solving service",
    ],
    "token_replay": [
        "captcha token replay", "captcha token reuse",
        "stale captcha token", "recycled captcha",
        "captcha response replay", "token harvesting captcha",
        "captcha token theft", "expired captcha reuse",
        "captcha nonce replay", "captcha session replay",
    ],
    "ocr_attack": [
        "ocr captcha attack", "optical recognition bypass",
        "captcha image ocr", "text captcha crack",
        "image recognition captcha", "captcha ml solve",
        "neural captcha break", "deep learning captcha",
        "captcha pattern recognition", "visual captcha crack",
    ],
    "audio_exploit": [
        "audio captcha exploit", "speech captcha bypass",
        "voice captcha crack", "audio challenge bypass",
        "captcha audio recognition", "speech-to-text captcha",
        "audio captcha bot", "voice recognition bypass",
        "captcha audio download", "sound captcha solve",
    ],
    "behavioral_spoof": [
        "behavioral captcha spoof", "mouse movement spoof",
        "human behavior simulation", "captcha interaction fake",
        "click pattern spoof", "typing pattern spoof",
        "recaptcha score manipulation", "captcha fingerprint spoof",
        "browser automation captcha", "headless browser captcha",
    ],
    "rate_flooding": [
        "captcha rate flood", "captcha brute force",
        "mass captcha attempt", "captcha enumeration",
        "rapid captcha request", "captcha dos attack",
        "captcha rate abuse", "flood captcha endpoint",
        "captcha resource exhaust", "bulk captcha challenge",
    ],
}


def classify_event(event):
    """Classify a single event into a CAPTCHA bypass category.

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
    """Analyze events for CAPTCHA bypass indicators.

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
    lines.append("CAPTCHA Bypass Detection Report")
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
