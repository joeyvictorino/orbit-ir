"""Detect HTTP request smuggling patterns in agent network activity.

HTTP request smuggling exploits discrepancies between how front-end and
back-end servers parse HTTP requests, enabling cache poisoning, request
hijacking, authentication bypass, and covert data exfiltration through
malformed Content-Length / Transfer-Encoding headers.
"""

from __future__ import annotations

import json
import re
from typing import Any

CATEGORIES: dict[str, str] = {
    "cl_te_desync": "Content-Length and Transfer-Encoding desync attack",
    "te_cl_desync": "Transfer-Encoding takes precedence over Content-Length",
    "te_te_obfuscation": "Transfer-Encoding header obfuscation to confuse parsers",
    "request_splitting": "Injected CRLF or headers to split a single request into two",
    "h2c_smuggling": "HTTP/2 cleartext upgrade used to bypass proxy restrictions",
    "websocket_smuggling": "WebSocket upgrade exploited to tunnel unauthorized requests",
}

_CL_TE_PATTERNS = [
    "content-length.*transfer-encoding", "cl.te", "cl-te desync",
    "content-length mismatch", "dual header", "ambiguous length",
    "conflicting content-length",
]

_TE_CL_PATTERNS = [
    "transfer-encoding.*content-length", "te.cl", "te-cl desync",
    "chunked.*content-length", "encoding precedence",
]

_TE_TE_PATTERNS = [
    "transfer-encoding.*transfer-encoding", r"\bte\.te\b", "te-te obfuscation",
    "chunked obfuscation", "malformed chunked", "encoding mutation",
    "xchunked", "chunked1",
]

_SPLITTING_PATTERNS = [
    "crlf injection", "request splitting", "header injection",
    r"\r\n", "line folding", "http desync", "request boundary",
    "smuggled request", "prefix injection",
]

_H2C_PATTERNS = [
    "h2c smuggling", "http2 cleartext", "upgrade: h2c",
    "http/2 upgrade", "h2c tunnel", "cleartext http2",
]

_WS_PATTERNS = [
    "websocket smuggling", "upgrade: websocket", "ws tunnel",
    "websocket tunnel", "ws smuggling", "socket upgrade",
]


def _match_any(text: str, patterns: list[str]) -> bool:
    for p in patterns:
        if re.search(p, text):
            return True
    return False


def classify_event(event: dict[str, Any]) -> str:
    """Classify a single event into an HTTP smuggling category."""
    text = " ".join(str(v) for v in event.values()).lower()

    if _match_any(text, _H2C_PATTERNS):
        return "h2c_smuggling"

    if _match_any(text, _WS_PATTERNS):
        return "websocket_smuggling"

    if _match_any(text, _TE_TE_PATTERNS):
        return "te_te_obfuscation"

    cl = event.get("content_length", "")
    te = event.get("transfer_encoding", "")
    if cl and te:
        if "chunked" in str(te).lower():
            return "te_cl_desync"
        return "cl_te_desync"

    if _match_any(text, _TE_CL_PATTERNS):
        return "te_cl_desync"

    if _match_any(text, _CL_TE_PATTERNS):
        return "cl_te_desync"

    if _match_any(text, _SPLITTING_PATTERNS):
        return "request_splitting"

    return "cl_te_desync"


def analyze(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze a list of events for HTTP smuggling patterns."""
    results: dict[str, Any] = {
        "total_events": len(events),
        "smuggling_events": 0,
        "categories": {cat: 0 for cat in CATEGORIES},
        "severity": "none",
        "findings": [],
    }

    if not events:
        return results

    for event in events:
        cat = classify_event(event)
        results["categories"][cat] += 1
        results["smuggling_events"] += 1
        results["findings"].append({
            "category": cat,
            "description": CATEGORIES[cat],
            "event_id": event.get("id", event.get("event_id", "unknown")),
            "content_length": event.get("content_length", ""),
            "transfer_encoding": event.get("transfer_encoding", ""),
        })

    total = results["smuggling_events"]
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
        "HTTP Request Smuggling Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:  {results['total_events']}",
        f"  Smuggling detected:     {results['smuggling_events']}",
        f"  Severity:               {results['severity']}",
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
                         f" CL={f['content_length']!r} TE={f['transfer_encoding']!r}")

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
