"""Ransomware attack detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "file_encryption": [
        "file encryption", "mass encryption", "encrypting files",
        "ransomware encryption", "crypto locker", "file locked",
        "encrypted extension", "ransom extension", "locked files",
        "bulk file modification",
    ],
    "ransom_note": [
        "ransom note", "ransom demand", "ransom message",
        "bitcoin payment", "cryptocurrency ransom", "decryption key demand",
        "readme ransom", "how to decrypt", "pay to unlock",
        "ransom instructions",
    ],
    "shadow_copy": [
        "shadow copy deletion", "vssadmin delete", "volume shadow",
        "backup deletion", "wmic shadowcopy", "bcdedit recovery",
        "disable recovery", "wbadmin delete", "delete backups",
        "recovery partition deleted",
    ],
    "lateral_spread": [
        "ransomware propagation", "worm spread", "smb propagation",
        "network share encryption", "lateral ransomware", "mass deployment",
        "psexec ransomware", "wmi remote execution", "self replication",
        "ransomware lateral movement",
    ],
    "defense_evasion": [
        "antivirus disabled", "defender disabled", "tamper protection off",
        "security tool killed", "edr bypass", "safe mode boot",
        "process hollowing ransomware", "disable logging",
        "event log cleared", "kill security process",
    ],
    "exfil_before_encrypt": [
        "double extortion", "data theft before encryption",
        "exfiltration then encrypt", "steal and encrypt",
        "data exfil ransomware", "pre-encryption exfil",
        "ransomware data leak", "leak site upload",
        "stolen data published", "extortion data theft",
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
        "Ransomware Detection Report",
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
