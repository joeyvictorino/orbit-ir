"""Protocol abuse detection for agent incident reconstruction."""

CATEGORIES = {
    "dns_tunneling": [
        "unusually long dns query",
        "encoded data in dns subdomain",
        "high volume dns txt record requests",
        "dns query to suspicious domain",
        "base64 encoded dns lookup",
        "dns exfiltration channel detected",
        "repeated dns queries with encoded payload",
        "dns response with embedded data",
        "covert dns communication channel",
        "dns tunneling tool signature",
    ],
    "http_smuggling": [
        "content-length transfer-encoding mismatch",
        "malformed http request boundary",
        "chunked encoding manipulation",
        "http request smuggling attempt",
        "ambiguous content-length header",
        "http desync attack pattern",
        "smuggled request in http pipeline",
        "double content-length header",
        "obfuscated transfer-encoding value",
        "http smuggling via line folding",
    ],
    "protocol_downgrade": [
        "tls downgrade to ssl",
        "forced http from https",
        "protocol version rollback",
        "cipher suite downgrade",
        "negotiation manipulation detected",
        "cleartext fallback triggered",
        "weak protocol version requested",
        "downgrade attack on handshake",
        "stripped security header",
        "forced insecure transport",
    ],
    "websocket_abuse": [
        "websocket origin bypass",
        "unauthorized websocket upgrade",
        "websocket frame injection",
        "cross-site websocket hijacking",
        "malformed websocket frame",
        "websocket tunnel for data exfil",
        "persistent websocket backdoor",
        "websocket protocol mismatch",
        "unvalidated websocket message",
        "websocket flood attack",
    ],
    "grpc_manipulation": [
        "grpc metadata injection",
        "unauthorized grpc reflection",
        "grpc deadline manipulation",
        "malformed protobuf payload",
        "grpc channel without tls",
        "grpc service enumeration",
        "grpc stream abuse detected",
        "protobuf deserialization exploit",
        "grpc authority header spoofing",
        "unary call flood on grpc endpoint",
    ],
    "icmp_covert": [
        "icmp payload with encoded data",
        "oversized icmp echo request",
        "icmp tunnel detected",
        "covert channel via icmp",
        "unusual icmp type code sequence",
        "icmp exfiltration pattern",
        "embedded command in icmp payload",
        "icmp redirect manipulation",
        "ping sweep with data payload",
        "icmp fragmentation abuse",
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
        "title": "Protocol Abuse Detection Report",
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
