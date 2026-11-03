"""API key leak detection module for agent incident reconstruction."""

import json

CATEGORIES = {
    "cloud_key_leak": [
        "aws access key", "aws secret key", "azure api key",
        "gcp service account key", "cloud credentials exposed",
        "iam key leaked", "cloud key in logs", "s3 key exposed",
        "azure connection string", "gcp api key leak",
    ],
    "token_exposure": [
        "api token exposed", "bearer token leaked", "oauth token in logs",
        "jwt secret exposed", "session token leak", "refresh token exposed",
        "access token logged", "auth token in url", "token in query string",
        "personal access token",
    ],
    "secret_in_code": [
        "hardcoded secret", "secret in source code", "api key in code",
        "credentials in repository", "secret committed", "key in git history",
        "password in source", "secret in config file", "plaintext credentials",
        "embedded api key",
    ],
    "key_misuse": [
        "api key abuse", "stolen api key", "unauthorized api access",
        "key used from unusual ip", "api key brute force",
        "rate limit bypass with key", "key sharing detected",
        "api key reuse", "compromised api key", "key used after revocation",
    ],
    "env_leak": [
        "environment variable leak", "env file exposed", "dotenv exposed",
        ".env in public repo", "environment secrets logged",
        "env variable in output", "secret in environment", "env dump",
        "printenv exposure", "environment variable disclosure",
    ],
    "webhook_secret": [
        "webhook secret exposed", "webhook token leaked",
        "signing secret compromised", "webhook key in logs",
        "notification secret leak", "callback secret exposed",
        "webhook authentication bypass", "hmac secret leaked",
        "webhook signature key", "integration secret exposed",
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
        "API Key Leak Detection Report",
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
