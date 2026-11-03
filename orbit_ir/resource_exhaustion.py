"""Resource exhaustion detection for agent incident reconstruction."""

CATEGORIES = {
    "cpu_spike": [
        "cpu usage exceeded threshold",
        "process consuming excessive cpu",
        "cpu bound loop detected",
        "runaway process cpu utilization",
        "sustained high cpu load",
        "cpu throttling triggered",
        "compute resource saturation",
        "cryptominer cpu pattern",
        "fork bomb cpu exhaustion",
        "tight loop cpu consumption",
    ],
    "memory_exhaustion": [
        "out of memory condition",
        "memory allocation failure",
        "heap exhaustion detected",
        "memory leak pattern observed",
        "oom killer invoked",
        "swap space exhausted",
        "memory pressure critical",
        "unbounded memory growth",
        "resident memory exceeded limit",
        "memory fragmentation severe",
    ],
    "disk_fill": [
        "disk space exhausted",
        "filesystem full condition",
        "inode exhaustion detected",
        "log file consuming all disk",
        "temp file accumulation",
        "disk write rate excessive",
        "storage quota exceeded",
        "partition full alert",
        "disk space rapidly declining",
        "uncontrolled file growth",
    ],
    "connection_flood": [
        "connection pool exhausted",
        "too many open connections",
        "syn flood detected",
        "socket exhaustion condition",
        "file descriptor limit reached",
        "connection backlog overflow",
        "half-open connection flood",
        "connection table full",
        "tcp connection storm",
        "listener queue saturated",
    ],
    "thread_starvation": [
        "thread pool exhausted",
        "worker thread starvation",
        "deadlocked thread detected",
        "thread count exceeded maximum",
        "goroutine leak detected",
        "async task queue backlog",
        "thread creation failure",
        "blocked thread accumulation",
        "executor service saturated",
        "concurrent task limit reached",
    ],
    "rate_limit_bypass": [
        "rate limit circumvented",
        "request throttle bypassed",
        "api quota exhaustion attack",
        "distributed rate limit evasion",
        "burst rate exceeded",
        "request flooding detected",
        "api abuse rate pattern",
        "throttle avoidance technique",
        "parallel request saturation",
        "rate limiting ineffective",
    ],
}


def classify_event(event_text):
    lower = event_text.lower()
    for category, indicators in CATEGORIES.items():
        for indicator in indicators:
            if indicator in lower:
                return category
    return "uncategorized"


def analyze(events):
    results = []
    category_counts = {}
    for ev in events:
        cat = classify_event(ev)
        results.append({"event": ev, "category": cat})
        category_counts[cat] = category_counts.get(cat, 0) + 1
    return {
        "title": "Resource Exhaustion Detection Report",
        "total_events": len(events),
        "categorized": sum(1 for r in results if r["category"] != "uncategorized"),
        "uncategorized": sum(1 for r in results if r["category"] == "uncategorized"),
        "category_counts": category_counts,
        "results": results,
    }


def format_report(analysis):
    lines = []
    lines.append(analysis["title"])
    lines.append("=" * len(analysis["title"]))
    lines.append(f"Total events: {analysis['total_events']}")
    lines.append(f"Categorized: {analysis['categorized']}")
    lines.append(f"Uncategorized: {analysis['uncategorized']}")
    lines.append("")
    lines.append("Category Breakdown:")
    for cat, count in sorted(analysis["category_counts"].items()):
        lines.append(f"  {cat}: {count}")
    lines.append("")
    lines.append("Details:")
    for r in analysis["results"]:
        lines.append(f"  [{r['category']}] {r['event']}")
    return "\n".join(lines)


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                events.append(stripped)
    return events
