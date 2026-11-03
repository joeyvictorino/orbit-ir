"""Detect domain fronting attack patterns in agent network activity.

Domain fronting abuses CDN and cloud provider infrastructure to hide
the true destination of HTTPS traffic by placing a different domain in
the SNI field vs. the Host header, enabling covert C2 channels and
data exfiltration that bypass network-level blocking.
"""

from __future__ import annotations

import json
import re
from typing import Any

CATEGORIES: dict[str, str] = {
    "sni_host_mismatch": "SNI field and Host header reference different domains",
    "cdn_abuse": "Legitimate CDN infrastructure used to relay covert traffic",
    "cloud_fronting": "Cloud provider endpoints used to front malicious domains",
    "tls_header_discrepancy": "TLS handshake domain differs from HTTP layer domain",
    "nested_tunnel": "Domain-fronted connection used as tunnel for further traffic",
    "fronting_chain": "Multiple domain fronting hops chained to obscure origin",
}

_CDN_PROVIDERS = [
    "cloudfront", "akamai", "fastly", "cloudflare", "azureedge",
    "googleapis", "gstatic", "amazonaws", "azure", "edgecastcdn",
]

_CLOUD_ENDPOINTS = [
    ".cloudfront.net", ".azureedge.net", ".appspot.com",
    ".cloudfunctions.net", ".execute-api.", ".amazonaws.com",
    ".azurewebsites.net", ".firebaseapp.com", ".netlify.app",
]

_FRONTING_INDICATORS = [
    "sni mismatch", "host header differs", "domain fronting",
    "fronted request", "cdn relay", "tls sni", "cloud front",
    "covert channel", "hidden destination", "disguised traffic",
    "fronting tunnel", "header discrepancy", "nested tunnel",
    "proxy chain", "relay hop",
]


def classify_event(event: dict[str, Any]) -> str:
    """Classify a single event into a domain fronting category."""
    text = " ".join(str(v) for v in event.values()).lower()

    if any(k in text for k in ("nested tunnel", "tunnel within", "double fronting", "relay chain")):
        return "nested_tunnel"

    if any(k in text for k in ("fronting chain", "multi-hop", "chained fronting", "hop chain")):
        return "fronting_chain"

    sni = event.get("sni", "").lower()
    host = event.get("host", event.get("host_header", "")).lower()
    if sni and host and sni != host:
        for ep in _CLOUD_ENDPOINTS:
            if ep in sni or ep in host:
                return "cloud_fronting"
        for cdn in _CDN_PROVIDERS:
            if cdn in sni or cdn in host:
                return "cdn_abuse"
        return "sni_host_mismatch"

    if any(k in text for k in ("cloud front", "cloud_fronting", "azure front", "appspot front")):
        return "cloud_fronting"

    if any(k in text for k in ("cdn relay", "cdn abuse", "cdn fronting", "edgecast", "akamai front")):
        return "cdn_abuse"

    if any(k in text for k in ("tls sni", "header discrepancy", "tls mismatch", "handshake domain")):
        return "tls_header_discrepancy"

    if any(k in text for k in ("sni mismatch", "host header differs", "domain front", "fronted request")):
        return "sni_host_mismatch"

    return "sni_host_mismatch"


def analyze(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze a list of events for domain fronting patterns."""
    results: dict[str, Any] = {
        "total_events": len(events),
        "domain_fronting_events": 0,
        "categories": {cat: 0 for cat in CATEGORIES},
        "severity": "none",
        "findings": [],
    }

    if not events:
        return results

    for event in events:
        cat = classify_event(event)
        results["categories"][cat] += 1
        results["domain_fronting_events"] += 1
        results["findings"].append({
            "category": cat,
            "description": CATEGORIES[cat],
            "event_id": event.get("id", event.get("event_id", "unknown")),
            "sni": event.get("sni", ""),
            "host": event.get("host", event.get("host_header", "")),
        })

    total = results["domain_fronting_events"]
    if total == 0:
        results["severity"] = "none"
    elif total <= 2:
        results["severity"] = "low"
    elif total <= 5:
        results["severity"] = "medium"
    elif total <= 10:
        results["severity"] = "high"
    else:
        results["severity"] = "critical"

    return results


def format_report(results: dict[str, Any]) -> str:
    """Format analysis results as a human-readable report."""
    lines = [
        "Domain Fronting Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:    {results['total_events']}",
        f"  Domain fronting detected:  {results['domain_fronting_events']}",
        f"  Severity:                  {results['severity']}",
        "",
        "  Category Breakdown:",
    ]

    for cat, count in results["categories"].items():
        if count > 0:
            lines.append(f"    {cat:30s} {count}")

    if results["findings"]:
        lines.append("")
        lines.append("  Findings:")
        for f in results["findings"][:20]:
            lines.append(f"    [{f['category']}] event={f['event_id']}"
                         f" sni={f['sni']!r} host={f['host']!r}")

    lines.append("")
    return "\n".join(lines)


def load_events(path: str) -> list[dict[str, Any]]:
    """Load events from a JSON file (array or newline-delimited)."""
    with open(path, "r") as fh:
        content = fh.read().strip()

    if content.startswith("["):
        return json.loads(content)

    events = []
    for line in content.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events
