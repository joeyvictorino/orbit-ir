"""Ransomware behavior detection for agent incident reconstruction."""

CATEGORIES = {
    "file_encryption": [
        "mass file rename with extension change",
        "rapid sequential file modification",
        "encryption library loaded dynamically",
        "file header overwritten with random bytes",
        "shadow copy deletion attempt",
        "volume snapshot removed",
        "file extension changed to .locked",
        "file extension changed to .encrypted",
        "bulk file access in short timeframe",
        "entropy increase in file contents",
    ],
    "ransom_note": [
        "ransom note file created",
        "readme.txt dropped in multiple directories",
        "how_to_decrypt instructions placed",
        "bitcoin wallet address found in file",
        "tor onion address in created file",
        "ransom demand text pattern detected",
        "help_decrypt file created",
        "payment instructions dropped",
        "decryption key offer in file",
        "countdown timer reference in note",
    ],
    "lateral_spread": [
        "smb share enumeration detected",
        "network drive mapping attempt",
        "worm-like propagation across hosts",
        "admin share access attempt",
        "psexec-style remote execution",
        "rdp brute force attempt",
        "credential harvesting for lateral movement",
        "network scanner activity detected",
        "port 445 scanning activity",
        "shared folder write access probe",
    ],
    "defense_evasion": [
        "antivirus service stopped",
        "windows defender disabled",
        "safe mode boot attempted",
        "event log cleared",
        "backup service terminated",
        "security tool process killed",
        "firewall rules modified to allow",
        "registry security settings changed",
        "system restore points deleted",
        "tamper protection bypassed",
    ],
    "exfiltration_threat": [
        "large data archive created before encryption",
        "data staged in temp directory",
        "outbound transfer of compressed archive",
        "cloud storage upload before encryption",
        "double extortion data theft detected",
        "sensitive file access before encryption wave",
        "database dump created",
        "email archive exported",
        "credential store copied",
        "bulk document access pattern",
    ],
    "persistence_mechanism": [
        "scheduled task created for re-encryption",
        "registry run key added for ransomware",
        "startup folder payload dropped",
        "boot sector modification detected",
        "service created for ransomware persistence",
        "cron job added for periodic encryption",
        "autorun entry created",
        "dll side-loading setup detected",
        "wmi subscription for persistence",
        "firmware-level persistence attempted",
    ],
}

ALL_INDICATORS = []
for cat, indicators in CATEGORIES.items():
    for ind in indicators:
        ALL_INDICATORS.append((cat, ind))


def classify_event(event):
    text = str(event.get("description", "")).lower()
    text += " " + str(event.get("action", "")).lower()
    text += " " + str(event.get("details", "")).lower()

    matches = []
    for category, indicator in ALL_INDICATORS:
        words = indicator.lower().split()
        if all(w in text for w in words):
            matches.append({"category": category, "indicator": indicator})
    return matches


def analyze(events):
    category_counts = {cat: 0 for cat in CATEGORIES}
    flagged = []

    for event in events:
        matches = classify_event(event)
        if matches:
            for m in matches:
                category_counts[m["category"]] += 1
            flagged.append({"event": event, "matches": matches})

    total = sum(category_counts.values())
    if total > 10:
        severity = "critical"
    elif total > 5:
        severity = "high"
    elif total > 0:
        severity = "medium"
    else:
        severity = "none"

    return {
        "detector": "ransomware_detection",
        "category_counts": category_counts,
        "total_indicators": total,
        "severity": severity,
        "flagged_events": flagged,
    }


def format_report(results):
    lines = ["Ransomware Detection Report", "=" * 40]
    lines.append(f"Severity: {results['severity']}")
    lines.append(f"Total indicators: {results['total_indicators']}")
    lines.append("")
    for cat, count in results["category_counts"].items():
        if count > 0:
            lines.append(f"  {cat}: {count}")
    lines.append("")
    for item in results["flagged_events"]:
        desc = item["event"].get("description", "unknown")
        cats = ", ".join(m["category"] for m in item["matches"])
        lines.append(f"  [{cats}] {desc}")
    return "\n".join(lines)


def load_events(path):
    import json
    with open(path) as f:
        return json.load(f)
