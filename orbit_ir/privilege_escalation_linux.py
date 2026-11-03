"""Linux privilege escalation detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "suid_abuse": [
        "suid binary", "setuid exploit", "suid exploitation",
        "find suid", "suid privilege", "setuid bit",
        "chmod +s", "suid root", "suid enumeration",
        "gtfobins suid",
    ],
    "kernel_exploit": [
        "kernel exploit", "kernel vulnerability", "dirty cow",
        "dirty pipe", "kernel privilege escalation", "kernel race condition",
        "overlayfs exploit", "kernel module exploit", "ptrace exploit",
        "kernel buffer overflow",
    ],
    "sudo_abuse": [
        "sudo misconfiguration", "sudo exploit", "sudo bypass",
        "sudoers abuse", "nopasswd sudo", "sudo vulnerability",
        "sudo token reuse", "sudo heap overflow", "sudo -l enumeration",
        "sudo privilege escalation",
    ],
    "cron_manipulation": [
        "cron job manipulation", "crontab hijack", "writable cron",
        "cron privilege escalation", "cron script injection",
        "cron path hijack", "malicious cron job", "cron wildcard injection",
        "crontab modification", "cron race condition",
    ],
    "container_escape": [
        "container escape", "docker escape", "container breakout",
        "privileged container exploit", "docker socket abuse",
        "mount namespace escape", "cgroup escape", "container root escape",
        "runc exploit", "kubernetes pod escape",
    ],
    "capability_abuse": [
        "linux capability abuse", "cap_sys_admin exploit", "capability escalation",
        "cap_setuid abuse", "cap_dac_override", "ambient capability",
        "capability bit manipulation", "cap_net_raw abuse",
        "cap_sys_ptrace exploit", "file capability abuse",
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
        "Linux Privilege Escalation Detection Report",
        "=" * 45,
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
