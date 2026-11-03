"""Detect configuration injection patterns in agent activity logs.

Identifies configuration manipulation attacks: environment variable injection,
config file tampering, runtime parameter poisoning, feature flag manipulation,
settings override, and deployment config corruption.
"""

import json
from collections import Counter

CATEGORIES = {
    "env_injection": [
        "env injection", "environment variable inject", "env var poisoning",
        "environment manipulation", "env override attack", "env path injection",
        "ld_preload inject", "library path inject",
        "env variable tamper", "process environment poison",
    ],
    "config_tamper": [
        "config tamper", "config file modified", "configuration corruption",
        "config overwrite", "settings file altered", "yaml injection",
        "json config poison", "toml tampering", "ini file injection",
        "config hot-reload exploit",
    ],
    "parameter_poison": [
        "parameter poison", "runtime parameter inject", "cli argument inject",
        "flag injection", "command line tamper", "startup parameter override",
        "argument smuggling", "parameter manipulation",
        "option injection", "switch injection",
    ],
    "feature_flag": [
        "feature flag manipulation", "feature toggle abuse", "flag override",
        "feature gate bypass", "dark launch exploit", "a/b test manipulation",
        "feature rollout tamper", "flag state corruption",
        "feature config inject", "gradual rollout abuse",
    ],
    "settings_override": [
        "settings override", "default override", "config precedence exploit",
        "settings injection", "preference manipulation", "user settings tamper",
        "global config override", "cascading config abuse",
        "config merge exploit", "settings escalation",
    ],
    "deploy_config": [
        "deploy config", "deployment tamper", "manifest injection",
        "helm values inject", "terraform config poison", "ansible vars inject",
        "pipeline config tamper", "ci/cd config inject",
        "infrastructure config", "gitops config poison",
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
    lines.append("Configuration Injection Detection Report")
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
