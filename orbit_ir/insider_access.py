"""Insider access abuse detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "unauthorized_access": [
        "unauthorized access", "access violation", "permission violation",
        "unauthorized login", "access control breach", "unauthorized entry",
        "access policy violation", "unauthorized system access",
        "unauthorized data access", "unauthorized resource access",
    ],
    "privilege_misuse": [
        "privilege misuse", "admin abuse", "elevated privilege abuse",
        "root access misuse", "superuser abuse", "privileged account misuse",
        "service account abuse", "role abuse",
        "permission escalation misuse", "authority abuse",
    ],
    "data_hoarding": [
        "data hoarding", "bulk data download", "mass file copy",
        "excessive data access", "data collection anomaly",
        "unusual download volume", "data accumulation",
        "bulk export", "mass data extraction", "stockpiling data",
    ],
    "off_hours_access": [
        "off hours access", "after hours login", "weekend access anomaly",
        "unusual time access", "night shift access", "non business hours",
        "late night login", "early morning access",
        "holiday access", "unusual login time",
    ],
    "policy_violation": [
        "security policy breach", "acceptable use violation",
        "data handling violation", "classification violation",
        "need to know violation", "separation of duties breach",
        "least privilege violation", "clean desk violation",
        "removable media violation", "compliance policy breach",
    ],
    "account_sharing": [
        "account sharing", "shared credentials", "credential sharing",
        "multiple location login", "simultaneous session",
        "shared password", "shared account access",
        "concurrent session anomaly", "impossible travel",
        "geographic anomaly",
    ],
}


def classify_event(event):
    if event is None:
        return "unknown"
    if isinstance(event, dict):
        text = " ".join(str(v) for v in event.values()).lower()
    elif isinstance(event, str):
        text = event.lower()
    else:
        return "unknown"
    if not text.strip():
        return "unknown"
    for category, indicators in CATEGORIES.items():
        for indicator in indicators:
            if indicator in text:
                return category
    return "unknown"


def analyze(events):
    total = len(events)
    flagged = []
    category_counts = {}

    for i, event in enumerate(events):
        cat = classify_event(event)
        if cat != "unknown":
            flagged.append({"index": i, "category": cat, "event": event})
            category_counts[cat] = category_counts.get(cat, 0) + 1

    flagged_count = len(flagged)
    if flagged_count > 10:
        severity = "critical"
    elif flagged_count > 5:
        severity = "high"
    elif flagged_count > 0:
        severity = "medium"
    else:
        severity = "none"

    return {
        "total_events": total,
        "flagged_count": flagged_count,
        "flagged_events": flagged,
        "category_counts": category_counts,
        "severity": severity,
        "detection_rate": flagged_count / total if total > 0 else 0.0,
    }


def format_report(result):
    lines = [
        "Insider Access Abuse Detection Report",
        "=" * 40,
        "",
        f"  Total events:      {result['total_events']}",
        f"  Flagged:           {result['flagged_count']}",
        f"  Severity:          {result['severity']}",
        f"  Detection rate:    {result['detection_rate']:.1%}",
        "",
    ]
    if result["category_counts"]:
        lines.append("  Categories:")
        for cat, count in sorted(result["category_counts"].items()):
            lines.append(f"    {cat:30s} {count}")
        lines.append("")

    shown = result["flagged_events"][:10]
    if shown:
        lines.append("  Flagged events:")
        for entry in shown:
            evt = str(entry["event"])[:80]
            lines.append(f"    [{entry['index']}] {entry['category']:20s} {evt}")
    if result["flagged_count"] > 10:
        lines.append(f"    ... and {result['flagged_count'] - 10} more")
    lines.append("")
    return "\n".join(lines)


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "events" in data:
            return data["events"]
        return [data]
    return [data]
