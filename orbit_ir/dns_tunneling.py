"""DNS tunneling pattern detection for agent incident reconstruction.

Detects patterns where agents use DNS as a covert communication channel:
- encoded_payloads: base64/hex encoded data in DNS query names
- high_query_volume: abnormally high DNS query rates from a single source
- long_subdomains: unusually long subdomain labels used for data exfiltration
- txt_record_abuse: misuse of TXT records for command-and-control payloads
- uncommon_record_types: use of rare DNS record types (NULL, CNAME chains) for tunneling
- query_pattern_anomaly: periodic or bursty DNS query patterns indicating automated tunneling
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "encoded_payloads": {
        "patterns": [
            r"(?i)(base64|hex)\w*\s+.{0,30}(payload|data|content).{0,20}(dns|query|subdomain)",
            r"(?i)(dns|query|subdomain).{0,20}(encod|base64|hex)\w*\s+(payload|data|content)",
            r"(?i)(encod|obfuscat)\w*\s+(dns|query|request)\s+(payload|name|label|data)",
            r"(?i)(encod|base64|hex)\w*\s+(payload|data).{0,20}(in|within)\s+(dns|query|subdomain)",
        ],
        "severity": "critical",
        "description": "Base64/hex encoded data embedded in DNS query names for covert data transfer",
    },
    "high_query_volume": {
        "patterns": [
            r"(?i)(high|abnormal|excessive|unusual|spike)\w*\s+(dns|query|request|lookup)\s+\w*\s*(volume|rate|count|frequency|traffic)",
            r"(?i)(dns|query|request)\s+(volume|rate|count|flood|burst).{0,20}(exceed|above|abnormal|high|spike|threshold)",
            r"(?i)(flood|burst|spike|surge)\w*\s+(of\s+)?(dns|query|request|lookup)",
            r"(?i)(dns|query)\s+(rate|frequency).{0,20}(limit|exceed|anomal|abnormal|threshold)",
        ],
        "severity": "high",
        "description": "Abnormally high DNS query rates suggesting automated tunneling activity",
    },
    "long_subdomains": {
        "patterns": [
            r"(?i)(long|lengthy|oversiz|extended|large)\s+(subdomain|label|hostname|domain.name|query.name)",
            r"(?i)(subdomain|label|hostname)\s+(length|size)\s+(exceed|above|abnormal|unusually|suspi)",
            r"(?i)(exfiltrat|tunnel|smuggl|transfer)\w*\s+.{0,30}(via|through|using)\s+(subdomain|label|dns)",
            r"(?i)(subdomain|label)\s+.{0,10}(encod|stuff|pack|embed)\w*\s+(data|payload|exfiltrat)",
        ],
        "severity": "critical",
        "description": "Unusually long subdomain labels used for data exfiltration via DNS",
    },
    "txt_record_abuse": {
        "patterns": [
            r"(?i)(txt|text)\s+(record|response)\s+(abuse|misuse|exploit|covert|suspicious|tunnel|c2|command)",
            r"(?i)(abuse|misuse|exploit|covert)\w*\s+(txt|text)\s+(record|response|lookup|query)",
            r"(?i)(command|control|c2|payload).{0,20}(via|through|using|in)\s+(txt|text)\s+(record|response)",
            r"(?i)(dns\s+txt|txt\s+record)\s+(channel|tunnel|exfil|beacon|callback)",
        ],
        "severity": "high",
        "description": "Misuse of DNS TXT records for command-and-control or payload delivery",
    },
    "uncommon_record_types": {
        "patterns": [
            r"(?i)(uncommon|rare|unusual|suspicious|unexpected)\s+.{0,10}(dns|record)\s+(type|query.type|rtype)",
            r"(?i)(null|cname.chain|srv|mx|ns)\s+(record|query)\s+(abuse|misuse|tunnel|covert|suspicious)",
            r"(?i)(dns\s+record\s+type).{0,10}(null|hinfo|rp|afsdb|loc)",
            r"(?i)(tunnel|covert|exfil)\w*\s+(via|through|using)\s+(null|cname|srv|mx|ns)\s+(record|query|type)",
        ],
        "severity": "high",
        "description": "Use of rare DNS record types for covert tunneling communication",
    },
    "query_pattern_anomaly": {
        "patterns": [
            r"(?i)(periodic|regular|bursty|rhythmic|timed)\s+(dns|query|request|lookup)\s+(pattern|interval|behavior|cadence)",
            r"(?i)(dns|query)\s+(pattern|behavior|cadence|interval).{0,20}(anomal|suspi|irregular|automat|periodic)",
            r"(?i)(automat|scripted|programm|bot)\w*\s+(dns|query|request|lookup)\s+(pattern|behavior|activity)",
            r"(?i)(beacon|heartbeat|polling|keepalive)\s+(pattern|behavior|signal).{0,20}(in|via|through|over)\s+(dns|query)",
        ],
        "severity": "critical",
        "description": "Periodic or bursty DNS query patterns indicating automated tunneling tools",
    },
}


@dataclass
class TunnelingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    query_name: str = ""
    record_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[TunnelingEvent] = field(default_factory=list)


@dataclass
class TunnelingChain:
    agent: str = ""
    steps: list[TunnelingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class DnsTunnelingReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[TunnelingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(dns.tunnel|encoded.payload|subdomain.exfil|"
    r"txt.record.abuse|query.flood|beacon.pattern|"
    r"covert.channel|data.exfiltration|c2.dns|dns.beacon)\b"
)


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


def _detect_chains(events: list[dict]) -> list[TunnelingChain]:
    agent_events: dict[str, list[TunnelingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            te = TunnelingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                query_name=str(ev.get("query_name", ev.get("domain", ""))),
                record_type=str(ev.get("record_type", "")),
                raw=ev,
            )
            agent_events[agent].append(te)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(TunnelingChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                violation_score=round(score, 2),
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


def analyze_dns_tunneling(events_or_dir: str | Path | list[dict]) -> DnsTunnelingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> DnsTunnelingReport:
    report = DnsTunnelingReport(total_events=len(events))
    cat_events: dict[str, list[TunnelingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = TunnelingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                query_name=str(ev.get("query_name", ev.get("domain", ""))),
                record_type=str(ev.get("record_type", "")),
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
    report.violation_chains = _detect_chains(events)
    return report


def format_text(report: DnsTunnelingReport) -> str:
    lines = [
        "DNS Tunneling Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Violation events: {report.violation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.violation_chains:
        lines.append("")
        lines.append("Violation chains:")
        for c in report.violation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.violation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: DnsTunnelingReport) -> str:
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
    for chain in data.get("violation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
