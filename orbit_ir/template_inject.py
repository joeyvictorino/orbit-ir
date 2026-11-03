"""Detect template injection attack indicators in agent behavior logs.

Identifies techniques for exploiting template engines: SSTI payloads,
Jinja exploits, Moustache abuse, expression language injection,
FreeMarker injection, and Velocity injection.
"""

import json
from collections import Counter

CATEGORIES = {
    "ssti_payload": [
        "ssti payload detected", "template injection attempt",
        "server-side template inject", "template expression eval",
        "template sandbox escape", "ssti rce payload", "template code exec",
        "template engine exploit", "ssti probe detected", "template eval inject",
    ],
    "jinja_exploit": [
        "jinja2 injection", "jinja template exploit", "jinja config access",
        "jinja mro traversal", "jinja subclass exploit", "jinja globals access",
        "jinja builtins access", "jinja lipsum exploit", "jinja cycler abuse",
        "jinja namespace inject",
    ],
    "moustache_abuse": [
        "moustache template inject", "handlebars injection",
        "mustache lookup exploit", "handlebars helper abuse",
        "mustache partial inject", "handlebars prototype",
        "mustache context escape", "handlebars exec helper",
        "mustache render exploit", "handlebars compile inject",
    ],
    "expression_language": [
        "expression language inject", "el injection detected",
        "spring el exploit", "jsp el injection", "ognl injection",
        "mvel expression inject", "spel payload", "el method invoke",
        "expression eval rce", "el property access",
    ],
    "freemarker_inject": [
        "freemarker injection", "freemarker exec", "freemarker new builtin",
        "freemarker template exploit", "freemarker assign inject",
        "freemarker object wrapper", "freemarker api exploit",
        "freemarker include inject", "freemarker macro abuse",
        "freemarker runtime exec",
    ],
    "velocity_inject": [
        "velocity injection", "velocity template exploit",
        "velocity class loader", "velocity runtime exec",
        "velocity evaluate inject", "velocity getclass exploit",
        "velocity forname abuse", "velocity reflection attack",
        "velocity engine exploit", "velocity context inject",
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
    lines.append("Template Injection Detection Report")
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
