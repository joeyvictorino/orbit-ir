"""Detect virtual machine escape attempt patterns in agent activity logs.

Identifies techniques that attempt to break out of virtualized
environments: hypervisor exploits, VM-to-host pivots, shared resource
abuse, virtual device attacks, memory mapping exploits, and guest-to-host
communication channel abuse.
"""

import json
from collections import Counter

CATEGORIES = {
    "hypervisor_exploit": [
        "hypervisor exploit", "vmm vulnerability", "hypercall abuse",
        "vmexit handler", "vmx exploit", "kvm exploit",
        "xen escape", "hyper-v exploit", "hypervisor code exec",
        "vmcs manipulation",
    ],
    "vm_host_pivot": [
        "vm to host", "guest to host pivot", "escape to hypervisor",
        "host filesystem access", "vm breakout", "host process inject",
        "vm escape lateral", "guest host boundary", "hypervisor shell",
        "host kernel access from guest",
    ],
    "shared_resource_abuse": [
        "shared folder exploit", "clipboard escape", "drag drop exploit",
        "shared memory vm", "paravirtual channel", "vmtools exploit",
        "guest additions vuln", "shared clipboard inject",
        "vmware tools escape", "vbox guest additions",
    ],
    "virtual_device_attack": [
        "virtual nic exploit", "emulated device vuln", "virtio exploit",
        "virtual gpu escape", "vfio attack", "pci passthrough exploit",
        "virtual usb attack", "emulated disk exploit",
        "virtual serial port", "para-virtualized device",
    ],
    "memory_mapping_exploit": [
        "dma attack vm", "mmio escape", "iommu bypass",
        "memory map exploit", "ept violation", "shadow page table",
        "nested paging attack", "balloon driver exploit",
        "memory overcommit abuse", "kvm mmu exploit",
    ],
    "guest_host_channel": [
        "vmci exploit", "vsock escape", "hgfs vulnerability",
        "rpci command inject", "backdoor port", "vmware backdoor",
        "hypervisor channel abuse", "vm communication interface",
        "guest rpc exploit", "vmbus escape",
    ],
}


def classify_event(event):
    """Classify a single event into a VM escape category.

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
    """Analyze events for VM escape attempt indicators.

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
    lines.append("VM Escape Attempt Detection Report")
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
