"""Phishing campaign detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "spear_phishing": [
        "spear phishing attack", "targeted phishing email", "personalized phish",
        "tailored phishing message", "spear-phishing campaign", "directed phishing attempt",
        "targeted social engineering email", "individualized phishing", "context-aware phish",
        "researched target phishing",
    ],
    "credential_harvest": [
        "credential harvesting page", "fake login portal", "credential phishing site",
        "password harvesting form", "credential theft landing page", "credential capture proxy",
        "login page impersonation", "credential stealing redirect", "harvested user credentials",
        "credential collection endpoint",
    ],
    "business_email_compromise": [
        "business email compromise", "bec attack", "ceo fraud email",
        "wire transfer fraud email", "invoice fraud phishing", "executive impersonation email",
        "vendor email compromise", "payment redirect fraud", "supplier invoice manipulation",
        "financial officer impersonation",
    ],
    "smishing": [
        "sms phishing attack", "smishing campaign", "text message phishing",
        "malicious sms link", "fraudulent text message", "sms credential theft",
        "mobile phishing text", "sms spoofed sender", "text message fraud scheme",
        "cellular phishing attempt",
    ],
    "whaling": [
        "whaling attack executive", "high-profile target phishing", "c-suite phishing attempt",
        "executive whaling campaign", "senior management phishing", "board member phishing",
        "vip targeted phishing", "whale phishing executive", "director-level phishing attack",
        "executive-targeted social engineering",
    ],
    "clone_phishing": [
        "clone phishing duplicate", "cloned email attack", "replicated email phishing",
        "copied legitimate email phishing", "email clone with malicious link",
        "duplicate email phishing campaign", "resent email with payload",
        "cloned notification phishing", "forged reply phishing", "mimicked email thread attack",
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
        "Phishing Campaign Detection Report",
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
