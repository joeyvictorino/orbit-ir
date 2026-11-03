"""Firmware rootkit detection in agent incident logs."""

import json
from pathlib import Path

CATEGORIES = {
    "firmware_modification": [
        "firmware flash",
        "uefi modification",
        "bios update",
        "spi flash write",
        "firmware overwrite",
        "nvram modification",
        "eeprom write",
    ],
    "boot_persistence": [
        "bootkit",
        "mbr modification",
        "vbr infection",
        "boot sector",
        "grub modification",
        "bootloader tamper",
        "initramfs inject",
    ],
    "hardware_implant": [
        "hardware implant",
        "bmc backdoor",
        "ipmi abuse",
        "baseboard management",
        "ilo exploit",
        "drac compromise",
        "hardware trojan",
    ],
    "driver_rootkit": [
        "kernel driver load",
        "unsigned driver",
        "driver injection",
        "rootkit module",
        "kernel module insert",
        "insmod unsigned",
        "driver hijack",
    ],
    "secure_boot_bypass": [
        "secure boot disable",
        "uefi variable",
        "mok manipulation",
        "boot verification",
        "shim bypass",
        "dbx modification",
        "platform key",
    ],
}


def classify_event(event: dict) -> list[str]:
    text = json.dumps(event).lower()
    return [cat for cat, patterns in CATEGORIES.items()
            if any(p in text for p in patterns)]


def analyze(events: list[dict]) -> dict:
    categories: dict = {}
    flagged = 0
    for ev in events:
        cats = classify_event(ev)
        if cats:
            flagged += 1
        for c in cats:
            categories.setdefault(c, {"count": 0, "events": []})
            categories[c]["count"] += 1
            categories[c]["events"].append(ev)
    risk = "low"
    if flagged > len(events) * 0.5:
        risk = "critical"
    elif flagged > len(events) * 0.3:
        risk = "high"
    elif flagged > len(events) * 0.1:
        risk = "medium"
    return {
        "categories": categories,
        "summary": {
            "total_events": len(events),
            "flagged_events": flagged,
            "risk_level": risk,
        },
    }


def format_report(analysis: dict) -> str:
    lines = ["Firmware Rootkit Detection Report", "=" * 40]
    s = analysis["summary"]
    lines.append(f"Total events: {s['total_events']}")
    lines.append(f"Flagged: {s['flagged_events']}")
    lines.append(f"Risk: {s['risk_level']}")
    lines.append("")
    for cat, info in sorted(analysis["categories"].items()):
        lines.append(f"  {cat}: {info['count']} events")
    return "\n".join(lines)


def load_events(path: str) -> list[dict]:
    return json.loads(Path(path).read_text())
