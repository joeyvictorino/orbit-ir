"""Detect keylogging activity indicators in agent behavior logs.

Identifies techniques associated with keystroke interception and input
capture: kernel-level hooking, API hooking, form grabbing, clipboard
monitoring, input device sniffing, and screen-based capture methods.
"""

import json
from collections import Counter

CATEGORIES = {
    "kernel_hooking": [
        "keyboard interrupt hook", "idt hook keyboard", "irp hook keybd",
        "kbdclass hook", "raw input intercept", "keyboard filter driver",
        "hid minidriver hook", "keyboard irp dispatch", "ps2 port sniff",
        "usb hid intercept",
    ],
    "api_hooking": [
        "setwindowshookex wh_keyboard", "getasynckeystate poll",
        "getkeystate monitor", "keybd_event intercept", "rawinput hook",
        "sendinput capture", "getkeynametextw hook", "mapvirtualkey monitor",
        "tounicode intercept", "nt user call hook",
    ],
    "form_grabbing": [
        "form submit intercept", "http post capture", "password field grab",
        "autofill data extract", "input element hook", "browser form steal",
        "credential form capture", "login page intercept", "web form grab",
        "post data sniff",
    ],
    "clipboard_monitoring": [
        "clipboard monitor", "openclipboard hook", "clipboard chain insert",
        "paste event capture", "clipboard data steal", "clipboard viewer add",
        "clipboard watcher", "clipboard change notify", "clipboard spy",
        "setclipboardviewer hook",
    ],
    "input_device_sniff": [
        "evdev sniff", "xinput monitor", "libinput intercept",
        "input event read", "keyboard device open", "dev input capture",
        "uinput inject", "input subsystem hook", "hid raw read",
        "keyboard scancode capture",
    ],
    "screen_capture_keylog": [
        "screenshot on keypress", "screen record input", "ocr keypress",
        "screen scrape password", "pixel capture input", "video keylog",
        "screenlog capture", "visual keylogger", "shoulder surf capture",
        "display buffer read",
    ],
}


def classify_event(event):
    """Classify a single event into a keylogger detection category.

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
    """Analyze events for keylogging activity indicators.

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
    lines.append("Keylogger Detection Report")
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
