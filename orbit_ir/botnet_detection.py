"""Botnet behavior detection for agent incident reconstruction."""

CATEGORIES = {
    "c2_communication": [
        "periodic beacon to known c2 server",
        "dns-based command channel detected",
        "irc channel join for command reception",
        "http-based c2 polling pattern",
        "encrypted c2 tunnel established",
        "domain generation algorithm activity",
        "fast-flux dns resolution pattern",
        "p2p botnet protocol detected",
        "tor hidden service c2 connection",
        "covert channel via dns txt records",
    ],
    "bot_enrollment": [
        "bot registration payload sent",
        "unique bot identifier generated",
        "system fingerprint transmitted to c2",
        "bot capability report sent upstream",
        "initial check-in with botmaster",
        "bot configuration downloaded",
        "campaign identifier received",
        "bot group assignment detected",
        "heartbeat interval configured",
        "update mechanism initialized",
    ],
    "ddos_capability": [
        "syn flood traffic generated",
        "udp amplification attack launched",
        "http flood request pattern",
        "slowloris connection holding detected",
        "dns amplification reflected",
        "ntp amplification attack traffic",
        "application layer flood detected",
        "volumetric attack traffic surge",
        "reflection attack source spoofing",
        "booter service api call detected",
    ],
    "spam_activity": [
        "mass email sending detected",
        "smtp relay abuse attempt",
        "spam template downloaded",
        "email harvesting activity",
        "email list received from c2",
        "phishing email campaign launched",
        "bounce message flood generated",
        "email header forging detected",
        "bulk mail queue buildup",
        "spam proxy relay configured",
    ],
    "credential_theft": [
        "keylogger module activated",
        "form grabber injected into browser",
        "credential intercept hook installed",
        "password dump transmitted to c2",
        "banking trojan overlay detected",
        "clipboard hijacker for crypto wallets",
        "session token stolen and relayed",
        "cookie jar exfiltrated to c2",
        "man-in-the-browser attack active",
        "two-factor bypass module loaded",
    ],
    "propagation": [
        "network worm scanning active",
        "exploit kit payload downloaded",
        "vulnerability scanner running on subnet",
        "lateral movement via smb exploit",
        "usb drive infection vector detected",
        "email attachment worm distributed",
        "drive-by download kit deployed",
        "social engineering lure created",
        "watering hole site compromised",
        "supply chain infection vector detected",
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
        "detector": "botnet_detection",
        "category_counts": category_counts,
        "total_indicators": total,
        "severity": severity,
        "flagged_events": flagged,
    }


def format_report(results):
    lines = ["Botnet Detection Report", "=" * 40]
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
