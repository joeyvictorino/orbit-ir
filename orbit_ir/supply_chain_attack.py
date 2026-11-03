"""Supply chain attack detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "dependency_confusion": [
        "dependency confusion", "namespace confusion", "package substitution",
        "internal package hijack", "private package spoof",
        "registry priority attack", "scope confusion", "dependency takeover",
        "package namespace squat", "internal dependency hijack",
    ],
    "typosquatting": [
        "typosquatting", "typo squat", "package name typo",
        "similar package name", "homoglyph package", "name confusion package",
        "misspelled dependency", "lookalike package", "combosquatting",
        "package impersonation",
    ],
    "build_pipeline_compromise": [
        "build pipeline compromise", "ci/cd compromise", "build server exploit",
        "pipeline injection", "build script tamper", "ci poisoning",
        "build environment compromise", "pipeline backdoor",
        "compromised build tool", "build artifact tampering",
    ],
    "package_poisoning": [
        "package poisoning", "malicious package", "backdoored package",
        "trojanized dependency", "compromised package", "supply chain malware",
        "poisoned library", "malicious module", "tainted package",
        "infected dependency",
    ],
    "update_hijack": [
        "update mechanism hijack", "update server compromise",
        "malicious update", "auto-update exploit", "update channel poison",
        "update signing bypass", "compromised update server",
        "update man-in-the-middle", "firmware update attack",
        "software update hijack",
    ],
    "code_signing_abuse": [
        "code signing abuse", "stolen signing key", "forged certificate",
        "signing key compromise", "certificate theft",
        "unauthorized code signing", "revoked certificate use",
        "self-signed masquerade", "signing infrastructure compromise",
        "certificate authority attack",
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
        "Supply Chain Attack Detection Report",
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
