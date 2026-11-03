"""Detect boot-level persistence mechanisms in agent activity logs.

Identifies techniques that establish persistence through boot process
manipulation: bootloader modification, boot sector infection, kernel
module injection, init system hijacking, scheduled startup tasks, and
firmware-level persistence.
"""

import json
from collections import Counter

CATEGORIES = {
    "bootloader_modification": [
        "grub modify", "bootloader overwrite", "boot.ini change",
        "bcdedit", "efi partition write", "uefi boot entry",
        "boot manager tamper", "mbr overwrite", "vbr modify",
        "bootmgr replace",
    ],
    "boot_sector_infection": [
        "mbr infection", "boot sector write", "volume boot record",
        "partition table modify", "disk sector zero", "raw disk write",
        "boot virus", "sector overwrite", "bootsector payload",
        "master boot record",
    ],
    "kernel_module_injection": [
        "insmod", "modprobe malicious", "kernel module load",
        "ko inject", "rootkit module", "driver load unsigned",
        "sys_init_module", "kmod insert", "lkm inject",
        "kernel extension load",
    ],
    "init_system_hijack": [
        "systemd unit create", "init.d script", "rc.local modify",
        "crontab boot", "launchd plist", "startup folder",
        "run key registry", "services.exe", "svchost inject",
        "xinetd config",
    ],
    "scheduled_startup": [
        "at boot schedule", "cron reboot", "task scheduler startup",
        "login hook", "logon script", "boot trigger task",
        "startup registry", "autorun entry", "shell startup",
        "profile script inject",
    ],
    "firmware_persistence": [
        "uefi implant", "spi flash write", "firmware rootkit",
        "bios reflash", "option rom inject", "smm handler",
        "tpm bypass", "secure boot disable", "firmware update malicious",
        "nvram modify",
    ],
}


def classify_event(event):
    """Classify a single event into a boot persistence category.

    Returns the category name or 'unknown'.
    """
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
    """Analyze events for boot-level persistence indicators.

    Returns a dict with category counts, flagged events, and summary stats.
    """
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
    """Format analysis results as a human-readable report."""
    lines = []
    lines.append("Boot-Level Persistence Detection Report")
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
    """Load events from a JSON file (list of event objects or strings)."""
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]
