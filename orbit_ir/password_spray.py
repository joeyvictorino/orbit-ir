"""Detect password spray attack patterns in agent activity logs.

Identifies password spraying techniques: low-and-slow authentication
attempts, credential rotation patterns, account lockout triggering,
protocol-specific spray vectors, distributed spray coordination, and
spray-then-pivot post-authentication behavior.
"""

import json
from collections import Counter

CATEGORIES = {
    "low_slow_auth": [
        "low and slow", "slow brute", "delayed authentication",
        "timed login attempt", "throttled spray", "paced credential",
        "rate-limited brute", "measured auth attempt",
        "distributed timing", "staggered login",
    ],
    "credential_rotation": [
        "password rotation spray", "credential list rotation",
        "password dictionary", "common password", "seasonal password",
        "default credential", "password reuse", "credential stuffing spray",
        "wordlist rotation", "top passwords",
    ],
    "lockout_trigger": [
        "account lockout", "lockout threshold", "lockout triggered",
        "auth failure threshold", "too many attempts",
        "locked account", "auth rate exceeded",
        "brute force lockout", "temporary lock",
        "progressive delay",
    ],
    "protocol_spray": [
        "smtp spray", "ldap spray", "kerberos spray",
        "ntlm spray", "oauth spray", "saml spray",
        "rdp spray", "ssh spray", "vpn spray",
        "web login spray",
    ],
    "distributed_spray": [
        "distributed spray", "multi-source spray", "botnet spray",
        "proxy rotation", "ip rotation spray", "residential proxy",
        "tor spray", "cloud function spray",
        "serverless spray", "lambda spray",
    ],
    "spray_then_pivot": [
        "spray then pivot", "post-spray lateral", "successful spray login",
        "spray access gained", "compromised via spray",
        "spray to mailbox", "spray privilege escalation",
        "spray credential valid", "spray initial access",
        "spray foothold",
    ],
}


def classify_event(event):
    """Classify a single event into a password spray category.

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
    """Analyze events for password spray attempt indicators.

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
    lines.append("Password Spray Detection Report")
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
