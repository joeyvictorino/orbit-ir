"""Network segmentation violation detection for agent incident reconstruction."""

import json
import sys

CATEGORIES = {
    "cross_zone_access": [
        "cross-zone connection", "zone boundary crossed", "inter-zone traffic",
        "dmz bypass detected", "trust zone violation", "segment boundary breach",
        "unauthorized zone access", "cross-segment communication",
        "zone traversal detected", "perimeter crossing",
    ],
    "flat_network": [
        "flat network topology", "no segmentation detected", "single subnet",
        "unsegmented network", "missing vlan isolation", "no micro-segmentation",
        "broad network access", "unrestricted lateral movement",
        "no network boundaries", "all-to-all connectivity",
    ],
    "firewall_bypass": [
        "firewall rule bypassed", "acl circumvented", "security group violated",
        "packet filter evaded", "ingress rule bypass", "egress filter bypass",
        "firewall exception exploited", "network policy circumvented",
        "rule base gap exploited", "filter evasion detected",
    ],
    "vlan_hopping": [
        "vlan hopping detected", "trunk port abuse", "double tagging attack",
        "switch spoofing detected", "vlan traversal", "802.1q exploit",
        "native vlan attack", "dynamic trunking exploited",
        "vlan encapsulation attack", "tag manipulation detected",
    ],
    "microseg_violation": [
        "microsegmentation violated", "workload isolation breach",
        "container network escape", "pod network violation",
        "namespace boundary crossed", "service mesh bypass",
        "sidecar proxy evaded", "network policy gap",
        "east-west traffic violation", "lateral policy bypass",
    ],
    "routing_abuse": [
        "route injection detected", "bgp hijack", "ospf manipulation",
        "routing table poisoned", "static route override",
        "gateway spoofing detected", "arp redirect abuse",
        "route leak detected", "prefix hijack",
        "routing protocol manipulation",
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
    lines.append("Network Segmentation Detection Report")
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
        print("Usage: python -m orbit_ir.network_segmentation <events.json>", file=sys.stderr)
        sys.exit(1)
    events = load_events(sys.argv[1])
    analysis = analyze(events)
    print(format_report(analysis))


if __name__ == "__main__":
    main()
