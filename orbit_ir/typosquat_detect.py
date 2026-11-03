"""Typosquatting domain detection for agent evidence.

Identifies typosquatting attack patterns in agent activity: homoglyph
substitution domains, transposition typos, missing/added character domains,
subdomain impersonation, punycode abuse, and combosquatting (appending
keywords to legitimate brands).
"""

import json
from collections import Counter

CATEGORIES = {
    "homoglyph_substitution": [
        "homoglyph domain", "lookalike character", "unicode substitution",
        "idn homograph", "visual spoof domain", "character swap domain",
        "cyrillic substitution", "greek letter spoof",
        "confusable character", "homograph attack",
    ],
    "transposition_typo": [
        "transposition domain", "swapped character", "letter swap",
        "typo domain", "keyboard adjacent", "adjacent key",
        "transposed letters", "character transposition",
        "misspelled domain", "typosquat registration",
    ],
    "missing_character": [
        "missing character domain", "omitted letter", "dropped character",
        "shortened domain", "truncated domain", "letter omission",
        "character deletion", "missing vowel domain",
        "stripped character", "abbreviated domain spoof",
    ],
    "added_character": [
        "extra character domain", "added letter", "character insertion",
        "doubled letter domain", "appended character", "prepended character",
        "inserted character", "padded domain",
        "extended domain name", "augmented domain",
    ],
    "subdomain_impersonation": [
        "subdomain impersonation", "subdomain spoof", "fake subdomain",
        "brand subdomain", "login subdomain", "secure subdomain spoof",
        "subdomain squatting", "nested subdomain",
        "multi-level subdomain", "deceptive subdomain",
    ],
    "combosquatting": [
        "combosquat", "brand keyword domain", "brand-login domain",
        "brand-secure domain", "brand-verify domain", "brand-update domain",
        "keyword appended domain", "brand-support domain",
        "brand-account domain", "brand combo domain",
    ],
}


def classify_event(event):
    """Classify a single event into a typosquatting category.

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
    """Analyze events for typosquatting attack indicators.

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

    severity = (
        "critical" if len(flagged) > 10
        else "high" if len(flagged) > 5
        else "medium" if len(flagged) > 0
        else "none"
    )

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
    lines.append("Typosquatting Detection Report")
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
