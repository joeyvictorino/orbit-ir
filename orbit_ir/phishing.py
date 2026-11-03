"""Phishing attack detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "spear_phishing": [
        "spear phishing", "targeted phishing", "whaling attack",
        "executive phishing", "ceo fraud", "business email compromise",
        "bec attack", "targeted email attack", "personalized phishing",
        "social engineering email",
    ],
    "credential_harvesting": [
        "credential harvesting", "credential phishing", "login page clone",
        "fake login", "password harvesting", "credential theft",
        "form grabber", "keylogger phishing", "credential capture",
        "authentication phishing",
    ],
    "url_spoofing": [
        "url spoofing", "link spoofing", "url obfuscation",
        "shortened url attack", "redirect chain", "open redirect exploit",
        "url masking", "link manipulation", "deceptive url",
        "typosquatting url",
    ],
    "homograph_attack": [
        "homograph attack", "idn homograph", "punycode attack",
        "unicode spoofing", "lookalike domain", "visual spoofing",
        "character substitution attack", "internationalized domain attack",
        "confusable character", "homoglyph attack",
    ],
    "email_impersonation": [
        "email impersonation", "display name spoofing", "from header spoofing",
        "email spoofing", "sender impersonation", "reply-to manipulation",
        "domain impersonation", "brand impersonation email",
        "cousin domain", "look-alike sender",
    ],
    "smishing": [
        "smishing", "sms phishing", "text message phishing",
        "sms spoofing", "text scam", "mobile phishing sms",
        "fraudulent text", "sms fraud", "text message scam",
    ],
    "vishing": [
        "vishing", "voice phishing", "phone phishing",
        "caller id spoofing", "phone scam", "voice social engineering",
        "robocall phishing", "phone fraud", "telephone phishing",
    ],
    "watering_hole": [
        "watering hole", "watering hole attack", "strategic web compromise",
        "compromised website", "drive-by download", "trusted site compromise",
        "supply chain web attack", "website poisoning",
        "legitimate site exploit", "targeted website compromise",
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
        "Phishing Attack Detection Report",
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
