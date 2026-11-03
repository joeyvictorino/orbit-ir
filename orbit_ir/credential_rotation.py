"""Credential rotation gap and failure detection for agent incident reconstruction."""

import json
import sys

CATEGORIES = {
    "stale_credential": [
        "credential not rotated", "expired api key", "key rotation overdue",
        "stale token detected", "rotation policy violated", "aging credential",
        "last rotated over", "credential age exceeds", "no rotation recorded",
        "static credential in use",
    ],
    "rotation_failure": [
        "rotation failed", "key renewal error", "credential update rejected",
        "rotation timeout", "failed to refresh token", "rotation rollback",
        "new credential invalid", "rotation aborted", "key generation failed",
        "rotation process crashed",
    ],
    "shared_credential": [
        "credential shared across", "same key multiple services",
        "duplicate credential detected", "shared secret between",
        "common credential usage", "credential reuse across",
        "identical token multiple", "shared api key", "cross-service credential",
        "multi-tenant same key",
    ],
    "weak_credential": [
        "weak key strength", "insufficient key length", "deprecated algorithm",
        "short-lived requirement unmet", "weak entropy detected",
        "predictable credential", "low complexity key", "insecure key format",
        "deprecated cipher suite", "weak hash function",
    ],
    "emergency_rotation": [
        "emergency rotation triggered", "breach-triggered rotation",
        "compromised credential revoked", "forced key rotation",
        "incident-driven renewal", "panic rotation executed",
        "credential leak response", "emergency revocation",
        "compromise-triggered refresh", "urgent key replacement",
    ],
    "rotation_gap": [
        "rotation window gap", "unrotated service credential",
        "rotation coverage incomplete", "missing rotation schedule",
        "no rotation policy defined", "rotation exempt detected",
        "uncovered credential type", "rotation blind spot",
        "gap in rotation coverage", "rotation schedule missing",
    ],
}


def classify_event(event):
    text = json.dumps(event).lower() if isinstance(event, dict) else str(event).lower()
    matches = {}
    for category, phrases in CATEGORIES.items():
        count = sum(1 for p in phrases if p in text)
        if count > 0:
            matches[category] = count
    return matches


def analyze(events):
    results = []
    category_totals = {c: 0 for c in CATEGORIES}
    for event in events:
        matches = classify_event(event)
        if matches:
            results.append({"event": event, "matches": matches})
            for cat, count in matches.items():
                category_totals[cat] += count
    return {
        "total_events": len(events),
        "flagged_events": len(results),
        "category_totals": category_totals,
        "results": results,
    }


def format_report(analysis):
    lines = []
    lines.append("Credential Rotation Detection Report")
    lines.append("=" * 50)
    lines.append(f"Total events analyzed: {analysis['total_events']}")
    lines.append(f"Flagged events: {analysis['flagged_events']}")
    lines.append("")
    lines.append("Category Totals:")
    for cat, total in sorted(analysis["category_totals"].items()):
        if total > 0:
            lines.append(f"  {cat}: {total}")
    lines.append("")
    for r in analysis["results"]:
        lines.append(f"Event: {r['event']}")
        for cat, count in sorted(r["matches"].items()):
            lines.append(f"  [{cat}] {count} match(es)")
        lines.append("")
    return "\n".join(lines)


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return [data]


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m orbit_ir.credential_rotation <events.json>", file=sys.stderr)
        sys.exit(1)
    events = load_events(sys.argv[1])
    analysis = analyze(events)
    print(format_report(analysis))


if __name__ == "__main__":
    main()
