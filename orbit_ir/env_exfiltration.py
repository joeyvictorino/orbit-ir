"""Detect environment variable exfiltration indicators in agent behavior logs.

Identifies techniques for stealing environment variables and runtime
configuration: direct env reads, process enumeration for env data,
/proc filesystem access, cloud metadata harvesting, env-to-network
exfiltration, and container runtime env exposure.
"""

import json
from collections import Counter

CATEGORIES = {
    "direct_env_read": [
        "environ read", "getenv sensitive", "os.environ access",
        "environment variable dump", "env var extract", "printenv capture",
        "export list dump", "env command output", "set command secrets",
        "process environment read",
    ],
    "proc_filesystem": [
        "/proc/self/environ", "/proc/pid/environ", "proc environ read",
        "cmdline extract secrets", "/proc/self/cmdline", "proc mount inspect",
        "/proc/self/maps secrets", "proc status read", "proc cgroup leak",
        "proc fd secrets",
    ],
    "cloud_metadata": [
        "metadata endpoint env", "instance metadata secrets",
        "iam role credential", "cloud metadata harvest",
        "azure imds token", "gcp metadata token", "aws sts assume",
        "169.254.169.254 env", "metadata api key", "cloud identity token",
    ],
    "network_exfil": [
        "env to http post", "dns encode env", "webhook env leak",
        "curl env variable", "env base64 send", "environment exfiltrate",
        "api key transmit", "secret token send", "env data upload",
        "outbound env payload",
    ],
    "container_runtime": [
        "docker inspect env", "container env list", "kubectl env extract",
        "docker exec env", "podman inspect secrets", "containerd env read",
        "cri-o env inspect", "oci runtime env", "container config secrets",
        "k8s secret mount read",
    ],
    "process_enumeration": [
        "ps aux env", "process list secrets", "wmic env extract",
        "tasklist env", "top env display", "htop env leak",
        "process explorer env", "task manager env", "systemctl env show",
        "service env dump",
    ],
}


def classify_event(event):
    """Classify a single event into an env exfiltration category.

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
    """Analyze events for environment variable exfiltration indicators.

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
    lines.append("Environment Variable Exfiltration Report")
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
