"""Detect BIOS/UEFI tampering patterns in agent activity logs.

Identifies attempts to modify, exploit, or subvert BIOS and UEFI firmware:
flash memory manipulation, secure boot bypass, SMM exploitation, NVRAM
corruption, option ROM injection, and TPM subversion.
"""

import json
from collections import Counter

CATEGORIES = {
    "flash_manipulation": [
        "spi flash write", "flash chip dump", "bios flash tool",
        "flashrom", "programmer spi", "flash erase",
        "firmware image extract", "flash region overwrite",
        "bios update unauthorized", "flash descriptor modify",
    ],
    "secure_boot_bypass": [
        "secure boot disable", "db variable modify", "mok enroll",
        "shim bypass", "boot policy override", "pk key replace",
        "kek manipulation", "dbx clear", "efi binary unsigned",
        "secure boot violation",
    ],
    "smm_exploitation": [
        "smm handler install", "smm callback", "smram access",
        "system management mode", "smi handler", "smm rootkit",
        "ring -2 access", "smm callout", "smbase modify",
        "smm privilege escalation",
    ],
    "nvram_corruption": [
        "nvram write", "efi variable modify", "uefi variable set",
        "nvram clear", "efi boot order change", "variable store corrupt",
        "runtime services modify", "nvram overflow", "variable authentication bypass",
        "efi monotonic counter",
    ],
    "option_rom_injection": [
        "option rom load", "pci rom modify", "expansion rom",
        "oprom inject", "pxe rom tamper", "nic rom flash",
        "gpu vbios modify", "raid rom replace", "pci config space",
        "rom bar manipulation",
    ],
    "tpm_subversion": [
        "tpm reset attack", "tpm interposer", "tpm bus sniff",
        "pcr extend spoof", "tpm seal bypass", "tpm firmware downgrade",
        "tpm owner clear", "endorsement key extract", "tpm replay attack",
        "platform configuration register",
    ],
}


def classify_event(event):
    """Classify a single event into a BIOS/UEFI tampering category.

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
    """Analyze events for BIOS/UEFI tampering indicators.

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
    lines.append("BIOS/UEFI Tampering Detection Report")
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
