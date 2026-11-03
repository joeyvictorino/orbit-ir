"""Network protocol abuse pattern detection for agent incident reconstruction.

Detects patterns where agents abuse network protocols:
- http_smuggling: HTTP request smuggling and desync attacks
- protocol_downgrade: forcing protocol version downgrades for exploitation
- header_injection: injecting malicious headers into protocol messages
- protocol_tunneling: tunneling unauthorized traffic through allowed protocols
- tls_stripping: stripping TLS to perform man-in-the-middle attacks
- protocol_fuzzing: fuzzing protocol implementations to find vulnerabilities
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "http_smuggling": {
        "patterns": [
            r"(?i)(http|request)\s+(smuggl|desync|split|pipeline.poison)",
            r"(?i)(smuggl|desync)\w*\s+(http|request|header|transfer.encoding|content.length)",
            r"(?i)(transfer.encoding|content.length)\s+(mismatch|conflict|ambiguous|duplicate)",
            r"(?i)(CL\.TE|TE\.CL|TE\.TE)\s*(attack|smuggl|exploit|desync)",
        ],
        "severity": "critical",
        "description": "HTTP request smuggling and desynchronization attacks",
    },
    "protocol_downgrade": {
        "patterns": [
            r"(?i)(protocol|tls|ssl|http)\s+(downgrade|fallback|version.roll|force.lower)",
            r"(?i)(downgrade|force|rollback)\w*\s+(to\s+)?(ssl|tls|http|protocol)\s*(version|v?\d)",
            r"(?i)(POODLE|DROWN|FREAK|Logjam)\s*(attack|exploit|vuln|downgrade)",
            r"(?i)(force|coerce|trick)\w*\s+(into\s+)?(plaintext|http|ssl\s*v?\d|tls\s*1\.?[01])",
        ],
        "severity": "critical",
        "description": "Forcing protocol version downgrades to exploit weaker implementations",
    },
    "header_injection": {
        "patterns": [
            r"(?i)(header|host|referer|cookie|user.agent)\s+(inject|poison|spoof|tamper|manipulat)",
            r"(?i)(inject|poison|spoof|tamper)\w*\s+(http\s+)?(header|host|cookie|referer|x-forwarded)",
            r"(?i)(CRLF|CR.LF|\\r\\n)\s+(inject|attack|split|smuggl)",
            r"(?i)(response\s+)?split(ting)?\s+(attack|via|through|using)\s+(header|CRLF|inject)",
        ],
        "severity": "high",
        "description": "Injecting malicious headers into protocol messages",
    },
    "protocol_tunneling": {
        "patterns": [
            r"(?i)(tunnel|encapsulat|wrap|embed)\w*\s+(traffic|data|payload|protocol)\s+(through|via|over|inside)\s+(http|dns|icmp|ssh|websocket)",
            r"(?i)(http|dns|icmp|ssh|websocket)\s+(tunnel|encapsulat|covert.channel|exfil)",
            r"(?i)(covert|hidden|stealth|unauthorized)\s+(tunnel|channel|traffic)\s+(via|through|over)\s+(allowed|legitimate|normal)\s+(protocol|port|service)",
            r"(?i)(bypass|evade|circumvent)\w*\s+(firewall|filter|proxy|ids|ips)\s+(via|through|using)\s+(tunnel|encapsulat)",
        ],
        "severity": "high",
        "description": "Tunneling unauthorized traffic through allowed protocols",
    },
    "tls_stripping": {
        "patterns": [
            r"(?i)(ssl|tls)\s+(strip|intercept|downgrade|remove|disable|bypass)",
            r"(?i)(strip|remove|disable|bypass)\w*\s+(ssl|tls|https|encryption|certificate)",
            r"(?i)(man.in.the.middle|mitm|mitmproxy)\s+(via|using|through)\s+(ssl|tls|strip|downgrade)",
            r"(?i)(sslstrip|ssl.strip|hsts\s+bypass|certificate\s+pin\s+bypass)",
        ],
        "severity": "critical",
        "description": "Stripping TLS encryption to perform man-in-the-middle attacks",
    },
    "protocol_fuzzing": {
        "patterns": [
            r"(?i)(protocol|http|tcp|udp|dns)\s+(fuzz|malform|corrupt|invalid|unexpected)",
            r"(?i)(fuzz|malform|corrupt)\w*\s+(protocol|packet|request|header|message|frame)",
            r"(?i)(send|inject|craft)\w*\s+(malform|invalid|corrupt|unexpected|oversiz)\w*\s+(packet|request|frame|message|header)",
            r"(?i)(crash|dos|denial|hang|resource.exhaust)\s+(via|through|using)\s+(malform|fuzz|invalid|corrupt)",
        ],
        "severity": "high",
        "description": "Fuzzing protocol implementations to discover vulnerabilities",
    },
}


@dataclass
class ProtocolAbuseEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    protocol: str = ""
    target_service: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ProtocolAbuseEvent] = field(default_factory=list)


@dataclass
class AbuseChain:
    agent: str = ""
    steps: list[ProtocolAbuseEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    abuse_score: float = 0.0


@dataclass
class ProtocolAbuseReport:
    total_events: int = 0
    abuse_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    abuse_chains: list[AbuseChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(http.smuggl|request.smuggl|protocol.downgrade|header.inject|"
    r"crlf.inject|protocol.tunnel|ssl.strip|tls.strip|mitm|"
    r"protocol.fuzz|packet.fuzz|desync)\b"
)

_PROTOCOL_RE = re.compile(r"(?i)\b(http|https|tcp|udp|dns|icmp|ssh|tls|ssl|websocket|ftp|smtp)\b")


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat in CATEGORIES:
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[AbuseChain]:
    agent_events: dict[str, list[ProtocolAbuseEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        matches = _classify_event(ev)
        for cat, technique in matches:
            proto_match = _PROTOCOL_RE.search(text)
            pa = ProtocolAbuseEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                protocol=proto_match.group(1).lower() if proto_match else "",
                target_service=str(ev.get("target", ev.get("service", ""))),
                raw=ev,
            )
            agent_events[agent].append(pa)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AbuseChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                abuse_score=round(score, 2),
            ))
    return chains[:20]


def _load_events(evidence_dir: str) -> list[dict]:
    events: list[dict] = []
    p = Path(evidence_dir)
    if not p.exists():
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


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def analyze_protocol_abuse(events_or_dir: str | Path | list[dict]) -> ProtocolAbuseReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ProtocolAbuseReport:
    report = ProtocolAbuseReport(total_events=len(events))
    cat_events: dict[str, list[ProtocolAbuseEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.abuse_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat, technique in matches:
            proto_match = _PROTOCOL_RE.search(text)
            e = ProtocolAbuseEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                protocol=proto_match.group(1).lower() if proto_match else "",
                target_service=str(ev.get("target", ev.get("service", ""))),
                raw=ev,
            )
            cat_events[cat].append(e)
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

    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * _SEVERITY_WEIGHT.get(cs.severity, 0.3)

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
    report.abuse_chains = _detect_chains(events)
    return report


def format_text(report: ProtocolAbuseReport) -> str:
    lines = [
        "Protocol Abuse Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Abuse events: {report.abuse_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.abuse_chains:
        lines.append("")
        lines.append("Abuse chains:")
        for c in report.abuse_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.abuse_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: ProtocolAbuseReport) -> str:
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
    for chain in data.get("abuse_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
