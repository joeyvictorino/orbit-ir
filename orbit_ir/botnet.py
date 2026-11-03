"""Botnet activity detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "c2_communication": [
        "command and control", "c2 server", "c2 channel", "c2 beacon",
        "botnet callback", "bot herder", "control server",
        "irc command channel", "botnet c2", "relay communication",
    ],
    "ddos_attack": [
        "ddos attack", "distributed denial", "syn flood", "udp flood",
        "http flood", "amplification attack", "volumetric attack",
        "botnet ddos", "traffic flood", "reflection attack",
    ],
    "bot_enrollment": [
        "bot enrollment", "botnet recruitment", "zombie enrollment",
        "bot registration", "new bot joined", "device compromised",
        "bot agent installed", "dropper executed", "payload delivered",
        "bot implant",
    ],
    "spam_relay": [
        "spam relay", "email spam bot", "mass mailing", "spam campaign",
        "bulk email", "phishing relay", "spam distribution",
        "email flood", "smtp abuse", "spam proxy",
    ],
    "credential_stuffing": [
        "credential stuffing", "brute force botnet", "password spray",
        "automated login", "account takeover bot", "login flood",
        "credential testing", "combo list", "stuffing attack",
        "distributed brute force",
    ],
    "crypto_mining_botnet": [
        "mining botnet", "crypto mining bot", "distributed mining",
        "mining pool botnet", "cryptojacking botnet", "bot miner",
        "mining payload", "hashrate hijack", "mining proxy botnet",
        "resource theft mining",
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
        "Botnet Detection Report",
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
