"""SSL/TLS stripping attack detection for agent incident reconstruction.

Detects patterns where agents exhibit SSL stripping behavior:
- https_downgrade: forced downgrade from HTTPS to HTTP
- certificate_spoofing: forged or self-signed certificates presented
- hsts_bypass: HSTS preload bypass, header stripping
- tls_interception: MITM TLS interception, proxy certificate injection
- protocol_downgrade: forced TLS version downgrade (TLS 1.3 -> 1.0)
- mixed_content_exploit: mixed HTTP/HTTPS content injection
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "https_downgrade": {
        "patterns": [
            r"(?i)(https)\s+(downgrad|strip|remov|rewrite|redirect)\w*\s+(to|into)?\s*(http)\w*",
            r"(?i)(strip|remov|downgrad)\w*\s+(ssl|tls|https|encrypt)\w*",
            r"(?i)(forc|redirect)\w*\s+(http)\b(?!\w*s)\w*\s+(instead|plain|unencrypt)\w*",
            r"(?i)(ssl\s*strip|sslstrip|ssl.strip)\w*",
        ],
        "severity": "critical",
        "description": "Forced downgrade from HTTPS to HTTP connections",
    },
    "certificate_spoofing": {
        "patterns": [
            r"(?i)(certific|cert)\w*\s+(spoof|forg|fake|self.sign|invalid|untrust)\w*",
            r"(?i)(self.sign|forged|fake|fraudulent)\w*\s+(certific|cert|ssl|tls)\w*",
            r"(?i)(present|inject|install)\w*\s+(fake|forged|rogue|untrust)\w*\s+(cert|ca|root)\w*",
            r"(?i)(certific|cert)\w*\s+(mismatch|error|warn|invalid|pin\s+violat)\w*",
        ],
        "severity": "critical",
        "description": "Forged or self-signed certificates, certificate spoofing",
    },
    "hsts_bypass": {
        "patterns": [
            r"(?i)(hsts)\s+(bypass|strip|remov|disabl|circumvent)\w*",
            r"(?i)(strict.transport)\s+(bypass|strip|remov|header)\w*",
            r"(?i)(strip|remov|delet)\w*\s+(hsts|strict.transport.security)\s+(header|polic)\w*",
            r"(?i)(preload|hsts)\w*\s+(list|bypass|evad|avoid)\w*",
        ],
        "severity": "high",
        "description": "HSTS preload bypass, Strict-Transport-Security header stripping",
    },
    "tls_interception": {
        "patterns": [
            r"(?i)(tls|ssl)\s+(intercept|mitm|man.in.the.middle|proxy)\w*",
            r"(?i)(mitm|man.in.the.middle)\w*\s+(tls|ssl|https|certific)\w*",
            r"(?i)(proxy)\s+(certific|cert|ca|root)\w*\s+(inject|instal|add|import)\w*",
            r"(?i)(intercept)\w*\s+(encrypt|tls|ssl|https)\w*\s+(traffic|connect|session)\w*",
        ],
        "severity": "high",
        "description": "MITM TLS interception, proxy certificate injection",
    },
    "protocol_downgrade": {
        "patterns": [
            r"(?i)(tls|ssl)\s+(version|protocol)\s+(downgrad|fallback|rollback)\w*",
            r"(?i)(downgrad|forc|fallback)\w*\s+(tls\s*(1\.0|1\.1)|ssl\s*(2|3)\.0)\w*",
            r"(?i)(poodle|beast|logjam|freak|drown)\w*\s+(attack|exploit|vuln)\w*",
            r"(?i)(cipher)\s+(suite|downgrad|weak|null|export)\w*\s+(forc|negoti|accept)\w*",
        ],
        "severity": "high",
        "description": "Forced TLS version downgrade, weak cipher negotiation",
    },
    "mixed_content_exploit": {
        "patterns": [
            r"(?i)(mixed)\s+(content|http)\w*\s+(inject|exploit|load|fetch)\w*",
            r"(?i)(inject|load|fetch)\w*\s+(http)\b(?!\w*s)\w*\s+(resource|script|style|image)\w*\s+(into|on)\s+(https)\w*",
            r"(?i)(http)\b(?!\w*s)\w*\s+(resource|script|iframe|asset)\w*\s+(on|within|embed)\w*\s+(https|secure)\w*",
            r"(?i)(insecure|plain)\w*\s+(resource|content|asset)\w*\s+(load|inject|embed)\w*\s+(secure|https)\w*",
        ],
        "severity": "medium",
        "description": "Mixed HTTP/HTTPS content injection on secure pages",
    },
}


@dataclass
class SslStrippingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_url: str = ""
    original_protocol: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[SslStrippingEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[SslStrippingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class SslStrippingReport:
    total_events: int = 0
    ssl_stripping_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(ssl.strip|https.downgrad|cert.spoof|self.sign|"
    r"hsts.bypass|tls.intercept|mitm.tls|protocol.downgrad|"
    r"poodle|beast|logjam|freak|drown|mixed.content|"
    r"cipher.downgrad|proxy.cert)\b"
)

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+")


def classify_event(event: dict) -> dict:
    text = " ".join(str(v) for v in event.values())
    best_cat = ""
    best_confidence = 0.0
    indicators: list[str] = []

    for cat in CATEGORIES:
        match_count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                match_count += 1
        if match_count > 0:
            confidence = min(1.0, match_count * 0.3)
            if confidence > best_confidence:
                best_confidence = confidence
                best_cat = cat
            indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = SslStrippingReport(total_events=len(events))
    cat_events: dict[str, list[SslStrippingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.ssl_stripping_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())

        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            url_match = _URL_RE.search(text)
            target_url = url_match.group(0) if url_match else ""
            proto = "https" if "https" in text.lower() else "http"

            ssl_ev = SslStrippingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_url=target_url,
                original_protocol=proto,
                raw=ev,
            )
            cat_events[cat].append(ssl_ev)
            if agent:
                agents_seen.add(agent)

    for cat, info in CATEGORIES.items():
        evts = cat_events[cat]
        report.categories.append(CategorySummary(
            category=cat,
            description=info["description"],
            count=len(evts),
            severity=info["severity"],
            events=evts[:10],
        ))

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * severity_weight.get(cs.severity, 0.3)

    if report.total_events > 0:
        report.risk_score = min(1.0, round(total_weighted / report.total_events, 2))

    if report.risk_score >= 0.5:
        report.risk_level = "critical"
    elif report.risk_score >= 0.3:
        report.risk_level = "high"
    elif report.risk_score >= 0.1:
        report.risk_level = "medium"
    elif report.risk_score > 0:
        report.risk_level = "low"
    else:
        report.risk_level = "none"

    report.agents_involved = sorted(agents_seen)
    report.attack_chains = _detect_chains(events)

    return _report_to_dict(report)


def _detect_chains(events: list[dict]) -> list[AttackChain]:
    agent_events: dict[str, list[SslStrippingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            ssl_ev = SslStrippingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(ssl_ev)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AttackChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                chain_score=round(score, 2),
            ))
    return chains[:20]


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
        return events
    for f in sorted(p.iterdir()):
        if f.suffix == ".json":
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except (json.JSONDecodeError, OSError):
                pass
    return events


def _report_to_dict(report: SslStrippingReport) -> dict:
    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            d = {}
            for k in obj.__dataclass_fields__:
                val = getattr(obj, k)
                if isinstance(val, list):
                    d[k] = [to_dict(v) if hasattr(v, "__dataclass_fields__") else v for v in val]
                else:
                    d[k] = val
            return d
        return obj

    data = to_dict(report)
    for cs in data.get("categories", []):
        for ev in cs.get("events", []):
            ev.pop("raw", None)
    for chain in data.get("attack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "SSL/TLS Stripping Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"SSL stripping events: {analysis.get('ssl_stripping_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("attack_chains", [])
    if chains:
        lines.append("")
        lines.append("Attack chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
