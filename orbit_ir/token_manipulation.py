"""Detect token and credential manipulation patterns in agent activity logs.

Identifies authentication token attacks: token forging, token replay,
token privilege escalation, session fixation, OAuth flow abuse, and
JWT token tampering.
"""

import json
from collections import Counter

CATEGORIES = {
    "token_forge": [
        "token forge", "forged auth token", "counterfeit token",
        "fabricated credential", "fake bearer token", "synthetic token",
        "token fabrication", "unsigned token creation",
        "token generation bypass", "crafted auth token",
    ],
    "token_replay": [
        "token replay", "replayed auth token", "credential replay attack",
        "captured token reuse", "stale token replay", "token resubmission",
        "auth replay detected", "replayed session token",
        "duplicate token submission", "token capture and replay",
    ],
    "token_escalation": [
        "token escalation", "privilege elevation via token",
        "token scope widening", "role escalation token",
        "admin token derivation", "token permission upgrade",
        "elevated token claim", "token authority boost",
        "scope expansion attack", "token privilege injection",
    ],
    "session_fixation": [
        "session fixation", "fixed session id", "session id injection",
        "pre-set session token", "session pinning attack",
        "forced session identifier", "session id manipulation",
        "session pre-assignment", "fixated session cookie",
        "session id planting",
    ],
    "oauth_abuse": [
        "oauth abuse", "oauth redirect manipulation", "authorization code theft",
        "oauth token interception", "consent screen bypass",
        "oauth scope escalation", "refresh token theft",
        "oauth flow hijack", "implicit grant abuse",
        "oauth state parameter bypass",
    ],
    "jwt_tamper": [
        "jwt tamper", "jwt signature bypass", "jwt algorithm confusion",
        "jwt none algorithm", "jwt claim modification",
        "jwt kid injection", "jwt header manipulation",
        "jwt payload alteration", "jwt expiry extension",
        "jwt key confusion attack",
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
    lines.append("Token Manipulation Detection Report")
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
