"""Detect hardware implant indicators in agent infrastructure logs.

Identifies signs of hardware-level compromise: rogue USB devices,
network tap implants, firmware backdoors, PCI/PCIe device injection,
JTAG/debug port exploitation, and hardware trojan indicators.
"""

import json
from collections import Counter

CATEGORIES = {
    "rogue_usb_device": [
        "unknown usb device", "usb device enumeration anomaly",
        "rubber ducky detect", "badusb indicator", "usb hid spoof",
        "unauthorized usb mass storage", "usb device class mismatch",
        "usb descriptor anomaly", "keystroke injection usb",
        "usb vendor id spoof",
    ],
    "network_tap_implant": [
        "network tap detected", "passive tap indicator", "inline tap device",
        "mirror port unauthorized", "span session rogue", "packet capture implant",
        "ethernet tap anomaly", "traffic duplication unexpected",
        "network bridge unauthorized", "promiscuous nic foreign",
    ],
    "firmware_backdoor": [
        "firmware checksum mismatch", "bios modification detected",
        "uefi unsigned module", "firmware version rollback",
        "baseboard management backdoor", "bmc unauthorized access",
        "ipmi firmware tamper", "firmware image altered",
        "option rom unauthorized", "pxe boot implant",
    ],
    "pci_device_injection": [
        "pci device unknown", "pcie hotplug unauthorized",
        "dma attack indicator", "thunderbolt dma", "firewire dma access",
        "pci bar anomaly", "pci config space tamper",
        "bus mastering unauthorized", "iommu bypass attempt",
        "pci device id spoof",
    ],
    "debug_port_exploit": [
        "jtag access detected", "debug port active",
        "serial console unauthorized", "uart access anomaly",
        "swd interface active", "debug interface enabled",
        "boundary scan detected", "on-chip debug", "jtag chain scan",
        "hardware debugger attached",
    ],
    "hardware_trojan": [
        "hardware trojan indicator", "chip-level anomaly",
        "power consumption anomaly", "electromagnetic emission anomaly",
        "timing side channel hardware", "silicon trojan",
        "hardware backdoor circuit", "logic bomb hardware",
        "counterfeit component", "supply chain hardware tamper",
    ],
}


def classify_event(event):
    """Classify a single event into a hardware implant category.

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
    """Analyze events for hardware implant indicators.

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
    lines.append("Hardware Implant Detection Report")
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
