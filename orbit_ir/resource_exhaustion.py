"""Detect resource exhaustion attack patterns in agent activity logs.

Identifies denial-of-service via resource exhaustion: CPU flooding,
memory bombs, disk space exhaustion, connection pool exhaustion,
thread pool starvation, and message queue overflow.
"""

import json
from collections import Counter

CATEGORIES = {
    "cpu_flood": [
        "cpu flood", "cpu exhaustion attack", "infinite loop inject",
        "compute bomb", "cpu spin attack", "processor saturation",
        "busy loop injection", "cpu starvation attack",
        "runaway process spawn", "cryptominer injection",
    ],
    "memory_bomb": [
        "memory bomb", "memory exhaustion attack", "heap spray",
        "memory allocation bomb", "oom trigger", "memory leak exploit",
        "unbounded allocation", "memory pressure attack",
        "ram exhaustion", "billion laughs attack",
    ],
    "disk_fill": [
        "disk fill", "disk exhaustion attack", "log flooding",
        "temp file bomb", "storage saturation", "disk space depletion",
        "write amplification attack", "inode exhaustion",
        "log rotation bypass", "cache poisoning overflow",
    ],
    "connection_flood": [
        "connection flood", "connection pool exhaustion",
        "socket exhaustion", "syn flood", "tcp connection bomb",
        "connection leak attack", "port exhaustion",
        "half-open connection flood", "connection table overflow",
        "keepalive abuse",
    ],
    "thread_starvation": [
        "thread starvation", "thread pool exhaustion",
        "worker thread depletion", "deadlock injection",
        "thread bomb attack", "goroutine leak", "async task flood",
        "executor exhaustion", "thread contention attack",
        "blocking call abuse",
    ],
    "queue_overflow": [
        "queue overflow", "message queue flood", "backlog exhaustion",
        "event queue saturation", "buffer overflow attack",
        "task queue bomb", "pubsub flood", "channel overflow",
        "mailbox exhaustion", "work queue depletion",
    ],
}


def classify_event(event):
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
    lines = []
    lines.append("Resource Exhaustion Detection Report")
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
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]
