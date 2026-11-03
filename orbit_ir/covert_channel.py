"""Covert channel detection for agent incident reconstruction.

Detects hidden communication channels between agents:
- steganographic_output: data encoded in output formatting, casing, or whitespace
- timing_signal: timing-based signaling between agents via response delays
- resource_encoding: resource usage patterns as information carriers
- metadata_abuse: metadata fields used for covert messaging between agents
- error_channel: error messages or codes used to pass hidden data
- protocol_tunnel: legitimate protocols tunneled for covert data transfer
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "steganographic_output": {
        "patterns": [
            r"(?i)(stegan|stego)\w*\s+(output|encod|embed|channel|data|message)",
            r"(?i)(hidden|covert|conceal)\w*\s+(data|message|signal|payload)\s+(in|via|through)\s+(output|format|text|whitespace|casing)",
            r"(?i)(encod|embed|hide)\w*\s+(data|info|message|signal)\s+(in|via|using)\s+(capitali|casing|spacing|punctuat|format)",
            r"(?i)(whitespace|spacing|indent|casing)\s+(encod|channel|signal|carrier|stegan)",
        ],
        "severity": "critical",
        "description": "Data encoded in output formatting, casing, or whitespace patterns",
    },
    "timing_signal": {
        "patterns": [
            r"(?i)(timing|delay|latency)\s+(signal|channel|encod|carrier|based)\w*",
            r"(?i)(covert|hidden)\s+(timing|delay|temporal)\s+(channel|signal|communicat)",
            r"(?i)(response|processing)\s+(delay|timing|latency)\s+(pattern|signal|anomal|unusual)",
            r"(?i)(synchroniz|coordinat)\w*\s+(via|through|using)\s+(timing|delay|interval|pause)",
        ],
        "severity": "high",
        "description": "Timing-based signaling between agents via response delays",
    },
    "resource_encoding": {
        "patterns": [
            r"(?i)(resource|cpu|memory|disk|bandwidth)\s+(usage|pattern|signal|encod|carrier|channel)",
            r"(?i)(covert|hidden)\s+(channel|signal|data)\s+(via|through|using)\s+(resource|cpu|memory|disk|allocation)",
            r"(?i)(encod|signal|transmit)\w*\s+(data|info|message)\s+(via|through|in)\s+(resource|usage|consumption|allocation)",
            r"(?i)(anomal|unusual|pattern)\w*\s+(resource|cpu|memory)\s+(usage|consumption|allocation|spike)",
        ],
        "severity": "high",
        "description": "Resource usage patterns used as information carriers",
    },
    "metadata_abuse": {
        "patterns": [
            r"(?i)(metadata|header|tag|label|annotation)\s+(abuse|misuse|exploit|channel|hidden|covert)",
            r"(?i)(hidden|covert|embed)\w*\s+(data|message|signal|payload)\s+(in|via|through)\s+(metadata|header|tag|label|field)",
            r"(?i)(extra|custom|unused)\s+(metadata|field|header|attribute)\s+(contain|carry|embed|encod)\w*\s+(data|message|signal|payload)",
            r"(?i)(stealth|covert|hidden)\s+(communicat|message|signal)\s+(via|through|using)\s+(metadata|header|tag|attribute)",
        ],
        "severity": "critical",
        "description": "Metadata fields used for covert messaging between agents",
    },
    "error_channel": {
        "patterns": [
            r"(?i)(error|exception|fault|failure)\s+(channel|signal|encod|carrier|message)\w*\s*(covert|hidden|stealth)?",
            r"(?i)(covert|hidden|stealth)\s+(communicat|data|signal|channel)\s+(via|through|using)\s+(error|exception|fault|status.code)",
            r"(?i)(error\s+code|status\s+code|return\s+code)\s+(encod|signal|carry|embed|hidden)\w*\s*(data|message|payload)?",
            r"(?i)(intentional|deliberate|craft)\w*\s+(error|exception|fault|failure)\s+(to|for)\s+(signal|communicat|transmit|encod)",
        ],
        "severity": "high",
        "description": "Error messages or codes used to pass hidden data",
    },
    "protocol_tunnel": {
        "patterns": [
            r"(?i)(protocol|dns|http|icmp)\s+(tunnel|covert|channel|encapsulat|piggyback)",
            r"(?i)(tunnel|encapsulat|piggyback)\w*\s+(data|payload|message|signal)\s+(via|through|in|over)\s+(dns|http|icmp|protocol|legitimate)",
            r"(?i)(covert|hidden|stealth)\s+(channel|tunnel|communicat)\s+(via|over|using)\s+(dns|http|icmp|protocol|api|websocket)",
            r"(?i)(dns|http|icmp|api)\s+(exfil|tunnel|covert|abuse|misuse)\w*\s*(channel|data|communicat)?",
        ],
        "severity": "critical",
        "description": "Legitimate protocols tunneled for covert data transfer",
    },
}


@dataclass
class ChannelEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ChannelEvent] = field(default_factory=list)


@dataclass
class ChannelChain:
    agent: str = ""
    steps: list[ChannelEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class CovertChannelReport:
    total_events: int = 0
    channel_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    channel_chains: list[ChannelChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(steganograph|timing.?channel|resource.?encod|metadata.?abuse|"
    r"error.?channel|protocol.?tunnel|dns.?tunnel|http.?tunnel|icmp.?tunnel|"
    r"whitespace.?encod|timing.?signal|covert.?channel)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[ChannelChain]:
    agent_events: dict[str, list[ChannelEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ce = ChannelEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(ChannelChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
            ))

    return chains[:20]


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


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


def analyze_covert_channels(events_or_dir: str | Path | list[dict]) -> CovertChannelReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> CovertChannelReport:
    report = CovertChannelReport(total_events=len(events))

    cat_events: dict[str, list[ChannelEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.channel_events += 1
        for cat, technique in matches:
            e = ChannelEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if technique:
                techniques_seen.add(technique)

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

    report.techniques_seen = sorted(techniques_seen)
    report.channel_chains = _detect_chains(events)

    return report


def format_text(report: CovertChannelReport) -> str:
    lines = [
        "Covert Channel Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Channel events: {report.channel_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.techniques_seen:
        lines.append("")
        lines.append(f"Techniques seen: {', '.join(report.techniques_seen)}")

    if report.channel_chains:
        lines.append("")
        lines.append("Channel chains:")
        for c in report.channel_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: CovertChannelReport) -> str:
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
    for chain in data.get("channel_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
