"""Detect protocol downgrade attack indicators in agent behavior logs.

Identifies techniques that force the use of weaker protocols or cipher
suites: TLS downgrade, HTTP downgrade, authentication weakening,
cipher suite manipulation, version rollback, and STARTTLS stripping.
"""

import json
from collections import Counter

CATEGORIES = {
    "tls_downgrade": [
        "tls version downgrade", "ssl fallback", "tls 1.0 negotiation",
        "ssl 3.0 connect", "tls_fallback_scsv bypass", "poodle attack",
        "tls renegotiation forced", "weak tls handshake", "ssl2 negotiation",
        "tlsv1 forced",
    ],
    "http_downgrade": [
        "https to http redirect", "http fallback", "mixed content load",
        "cleartext redirect", "http downgrade", "ssl strip",
        "secure to insecure", "port 80 redirect", "unencrypted fallback",
        "protocol downgrade http",
    ],
    "auth_weakening": [
        "ntlm downgrade", "kerberos to ntlm", "oauth downgrade",
        "saml version lower", "digest to basic", "mfa bypass downgrade",
        "auth method weakened", "strong to weak auth", "credential downgrade",
        "token type weaken",
    ],
    "cipher_manipulation": [
        "weak cipher suite", "export cipher", "null cipher",
        "rc4 cipher negotiated", "des cipher forced", "cipher suite downgrade",
        "anon cipher selected", "no forward secrecy", "weak key exchange",
        "md5 signature forced",
    ],
    "version_rollback": [
        "protocol version rollback", "version negotiation tamper",
        "client hello modify", "server hello tamper", "version field alter",
        "handshake message modify", "extension strip", "capability remove",
        "feature downgrade", "backward compat force",
    ],
    "starttls_strip": [
        "starttls strip", "starttls command remove", "smtp cleartext",
        "imap starttls block", "pop3 starttls strip", "xmpp tls strip",
        "ftp auth tls block", "ldap tls strip", "starttls intercept",
        "opportunistic tls block",
    ],
}


def classify_event(event):
    """Classify a single event into a protocol downgrade category.

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
    """Analyze events for protocol downgrade attack indicators.

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
    lines.append("Protocol Downgrade Detection Report")
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
