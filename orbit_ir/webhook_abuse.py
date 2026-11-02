"""Webhook and callback endpoint abuse detection in agent evidence.

Identifies agents abusing webhook/callback mechanisms to exfiltrate data,
establish covert communication channels, trigger unauthorized actions,
or manipulate external systems through crafted callback payloads.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


WEBHOOK_ABUSE_KEYWORDS = {
    "webhook abuse", "callback abuse", "webhook exploit",
    "malicious webhook", "webhook injection", "callback injection",
    "webhook manipulation", "unauthorized callback", "webhook hijack",
    "callback hijack",
}

WEBHOOK_EXFIL_KEYWORDS = {
    "webhook exfiltration", "callback exfiltration", "data via webhook",
    "exfil callback", "data to webhook", "webhook data leak",
    "send to callback", "webhook channel", "callback tunnel",
    "outbound webhook",
}

WEBHOOK_FORGE_KEYWORDS = {
    "forge webhook", "fake callback", "spoof webhook",
    "webhook forgery", "callback forgery", "webhook impersonation",
    "fake webhook", "crafted callback", "webhook payload injection",
    "callback payload manipulation",
}

WEBHOOK_FLOOD_KEYWORDS = {
    "webhook flood", "callback storm", "webhook dos",
    "callback flood", "webhook spam", "callback bombardment",
    "webhook rate abuse", "excessive callbacks", "webhook amplification",
}

SSRF_KEYWORDS = {
    "ssrf", "server-side request forgery", "internal endpoint",
    "localhost callback", "127.0.0.1 callback", "internal webhook",
    "metadata endpoint", "cloud metadata", "169.254.169.254",
    "internal url", "private ip callback",
}

WEBHOOK_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]{5,}(?:webhook|callback|hook|notify|event)[^\s"\'<>]*',
    re.IGNORECASE,
)

INTERNAL_IP_PATTERN = re.compile(
    r'(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|localhost)',
    re.IGNORECASE,
)


@dataclass
class WebhookAbusePattern:
    pattern_type: str
    agent_id: str
    evidence_file: str
    matched_keywords: list[str] = field(default_factory=list)
    urls_found: list[str] = field(default_factory=list)
    context: str = ""
    severity: str = "medium"
    chain_id: str | None = None


@dataclass
class WebhookAbuseSummary:
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    agents_involved: int = 0
    chains_detected: int = 0
    unique_urls: int = 0


@dataclass
class WebhookAbuseReport:
    patterns: list[WebhookAbusePattern] = field(default_factory=list)
    summary: WebhookAbuseSummary = field(default_factory=WebhookAbuseSummary)


def analyze_webhook_abuse(evidence_dir: Path) -> WebhookAbuseReport:
    events = _load_events(evidence_dir)
    report = WebhookAbuseReport()
    agents: set[str] = set()
    all_urls: set[str] = set()

    for ev in events:
        agent_id = ev.get("agent_id", ev.get("agent", "unknown"))
        src = ev.get("_source_file", "unknown")
        text = json.dumps(ev).lower()

        urls = WEBHOOK_URL_PATTERN.findall(text)
        all_urls.update(urls)

        for pat in _detect_webhook_abuse(text, agent_id, src, urls):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_webhook_exfil(text, agent_id, src, urls):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_webhook_forge(text, agent_id, src, urls):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_webhook_flood(text, agent_id, src, urls):
            report.patterns.append(pat)
            agents.add(agent_id)

        for pat in _detect_ssrf_via_webhook(text, agent_id, src):
            report.patterns.append(pat)
            agents.add(agent_id)

    for p in report.patterns:
        p.severity = _classify_severity(p)

    _detect_abuse_chains(report)

    s = report.summary
    s.total_patterns = len(report.patterns)
    s.agents_involved = len(agents)
    s.unique_urls = len(all_urls)
    for p in report.patterns:
        s.by_type[p.pattern_type] = s.by_type.get(p.pattern_type, 0) + 1
        s.by_severity[p.severity] = s.by_severity.get(p.severity, 0) + 1
    s.chains_detected = len({p.chain_id for p in report.patterns if p.chain_id})

    return report


def _detect_webhook_abuse(text: str, agent_id: str, src: str, urls: list[str]) -> list[WebhookAbusePattern]:
    matched = [kw for kw in WEBHOOK_ABUSE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [WebhookAbusePattern(
        pattern_type="webhook-abuse",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        urls_found=urls[:5],
        context=text[:200],
    )]


def _detect_webhook_exfil(text: str, agent_id: str, src: str, urls: list[str]) -> list[WebhookAbusePattern]:
    matched = [kw for kw in WEBHOOK_EXFIL_KEYWORDS if kw in text]
    if not matched:
        return []
    return [WebhookAbusePattern(
        pattern_type="webhook-exfiltration",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        urls_found=urls[:5],
        context=text[:200],
    )]


def _detect_webhook_forge(text: str, agent_id: str, src: str, urls: list[str]) -> list[WebhookAbusePattern]:
    matched = [kw for kw in WEBHOOK_FORGE_KEYWORDS if kw in text]
    if not matched:
        return []
    return [WebhookAbusePattern(
        pattern_type="webhook-forgery",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        urls_found=urls[:5],
        context=text[:200],
    )]


def _detect_webhook_flood(text: str, agent_id: str, src: str, urls: list[str]) -> list[WebhookAbusePattern]:
    matched = [kw for kw in WEBHOOK_FLOOD_KEYWORDS if kw in text]
    if not matched:
        return []
    return [WebhookAbusePattern(
        pattern_type="webhook-flood",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        urls_found=urls[:5],
        context=text[:200],
    )]


def _detect_ssrf_via_webhook(text: str, agent_id: str, src: str) -> list[WebhookAbusePattern]:
    matched = [kw for kw in SSRF_KEYWORDS if kw in text]
    if not matched:
        return []
    internal_ips = INTERNAL_IP_PATTERN.findall(text)
    return [WebhookAbusePattern(
        pattern_type="ssrf-via-webhook",
        agent_id=agent_id,
        evidence_file=src,
        matched_keywords=matched,
        urls_found=internal_ips[:5],
        context=text[:200],
        severity="critical",
    )]


def _classify_severity(p: WebhookAbusePattern) -> str:
    if p.pattern_type == "ssrf-via-webhook":
        return "critical"
    if p.pattern_type == "webhook-exfiltration":
        return "high"
    if p.pattern_type == "webhook-forgery":
        return "high"
    if len(p.matched_keywords) >= 3:
        return "high"
    return "medium"


def _detect_abuse_chains(report: WebhookAbuseReport) -> None:
    by_agent: dict[str, list[WebhookAbusePattern]] = defaultdict(list)
    for p in report.patterns:
        by_agent[p.agent_id].append(p)

    chain_id = 0
    for agent_id, pats in by_agent.items():
        types = {p.pattern_type for p in pats}
        if len(types) >= 2:
            chain_id += 1
            cid = f"webhook-chain-{chain_id}"
            for p in pats:
                p.chain_id = cid
                if p.severity != "critical":
                    p.severity = "high"


def format_text(report: WebhookAbuseReport) -> str:
    lines = ["Webhook / Callback Abuse Analysis", "=" * 40, ""]
    if not report.patterns:
        lines.append("No webhook abuse patterns detected.")
        return "\n".join(lines)

    for p in report.patterns:
        chain = f" [chain: {p.chain_id}]" if p.chain_id else ""
        lines.append(f"  [{p.severity}] {p.pattern_type} — agent={p.agent_id}{chain}")
        lines.append(f"    keywords: {', '.join(p.matched_keywords)}")
        if p.urls_found:
            lines.append(f"    urls: {', '.join(p.urls_found[:3])}")
        lines.append(f"    file: {p.evidence_file}")
        lines.append("")

    s = report.summary
    lines.append(f"Summary: {s.total_patterns} patterns, {s.agents_involved} agents, {s.unique_urls} unique URLs, {s.chains_detected} chains")
    for t, c in sorted(s.by_type.items()):
        lines.append(f"  {t}: {c}")
    return "\n".join(lines)


def format_json(report: WebhookAbuseReport) -> str:
    return json.dumps(asdict(report), indent=2)


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not evidence_dir.is_dir():
        return events
    for f in sorted(evidence_dir.iterdir()):
        if f.suffix != ".json":
            continue
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    item["_source_file"] = f.name
                    events.append(item)
        elif isinstance(data, dict):
            data["_source_file"] = f.name
            events.append(data)
    return events
