"""Cryptojacking detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "mining_pool": [
        "mining pool", "stratum protocol", "stratum+tcp", "pool connection",
        "mining proxy", "hashrate submit", "pool.minexmr", "nanopool",
        "nicehash", "f2pool",
    ],
    "cpu_abuse": [
        "cpu mining", "cpu miner", "high cpu usage mining",
        "xmrig", "cpuminer", "minergate",
        "cryptonight", "randomx", "cpu resource abuse",
    ],
    "gpu_abuse": [
        "gpu mining", "cuda miner", "opencl mining", "gpu resource abuse",
        "ethereum miner", "ethash", "kawpow", "gpu compute hijack",
        "nvidia mining", "amd mining",
    ],
    "browser_mining": [
        "browser mining", "coinhive script", "cryptoloot", "webminer",
        "javascript miner", "wasm miner", "browser crypto",
        "in-browser mining", "web-based miner", "cryptonight wasm",
    ],
    "container_mining": [
        "container mining", "docker miner", "kubernetes mining",
        "container escape mining", "pod mining", "cryptojacking container",
        "malicious container image", "mining docker image",
        "container resource abuse", "pod resource hijack",
    ],
    "wallet_activity": [
        "mining wallet", "monero wallet", "crypto wallet address",
        "bitcoin address", "wallet payout", "mining reward",
        "cryptocurrency transfer", "wallet connection",
        "mining earnings", "hash rate payout",
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
        "Cryptojacking Detection Report",
        "=" * 40,
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
