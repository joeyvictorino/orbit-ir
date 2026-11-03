"""Network probing detection for agent incident reconstruction.

Detects patterns where agents perform unauthorized network reconnaissance:
- port_scanning: scanning for open ports on target hosts
- service_discovery: enumerating running services and versions
- dns_enumeration: querying DNS records for reconnaissance
- network_mapping: mapping network topology and routes
- vulnerability_scanning: scanning for known vulnerabilities
- banner_grabbing: collecting service banners for fingerprinting
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "port_scanning": {
        "patterns": [
            r"(?i)(port|tcp|udp)\s+(scan|sweep|prob|enumerat|check)\w*",
            r"(?i)(scan|sweep|prob)\w*\s+(port|tcp|udp)\s*(range|list|block)?",
            r"(?i)(nmap|masscan|zmap|rustscan)\s+(scan|run|execut)",
            r"(?i)(open|closed|filtered)\s+(port|service)\s+(detect|found|discover)",
        ],
        "severity": "high",
        "description": "Scanning for open ports on target hosts",
    },
    "service_discovery": {
        "patterns": [
            r"(?i)(service|daemon|process)\s+(discover|enumerat|fingerprint|detect|identif)",
            r"(?i)(discover|enumerat|identif|fingerprint)\w*\s+(running\s+)?(service|daemon|application|server)",
            r"(?i)(service|version)\s+(detection|fingerprint|enumeration|identification|probe)",
            r"(?i)(enumerate|list|discover)\w*\s+(available|running|active|listening)\s+(service|server|endpoint)",
        ],
        "severity": "high",
        "description": "Enumerating running services and their versions",
    },
    "dns_enumeration": {
        "patterns": [
            r"(?i)(dns|domain)\s+(enumerat|recon|brute.?force|zone.?transfer|lookup|query)",
            r"(?i)(enumerat|recon|brute.?force)\w*\s+(dns|domain|subdomain|hostname)",
            r"(?i)(zone.?transfer|axfr|dig|nslookup|host)\s+(attempt|query|request|enumerat)",
            r"(?i)(subdomain|hostname|domain)\s+(enumerat|brute.?force|discover|scan|fuzz)",
        ],
        "severity": "high",
        "description": "Querying DNS records for network reconnaissance",
    },
    "network_mapping": {
        "patterns": [
            r"(?i)(network|subnet|route|topology)\s+(map|scan|discover|enumerat|trac)",
            r"(?i)(map|discover|enumerat|trac)\w*\s+(network|subnet|route|topology|infrastructure)",
            r"(?i)(traceroute|tracert|ping.sweep|arp.scan|netdiscover)\s+(run|execut|perform)",
            r"(?i)(internal|external)\s+(network|infrastructure)\s+(recon|map|scan|discover)",
        ],
        "severity": "critical",
        "description": "Mapping network topology and routing paths",
    },
    "vulnerability_scanning": {
        "patterns": [
            r"(?i)(vulnerability|vuln|cve)\s+(scan|check|assess|detect|prob)",
            r"(?i)(scan|check|assess|prob)\w*\s+(for\s+)?(vulnerability|vuln|cve|exploit|weakness)",
            r"(?i)(nessus|openvas|nikto|nuclei|qualys)\s+(scan|run|execut|launch)",
            r"(?i)(exploit|attack)\s+(surface|vector)\s+(scan|enumerat|assess|map)",
        ],
        "severity": "critical",
        "description": "Scanning for known vulnerabilities on target systems",
    },
    "banner_grabbing": {
        "patterns": [
            r"(?i)(banner|header)\s+(grab|collect|captur|extract|retriev)",
            r"(?i)(grab|collect|captur|extract)\w*\s+(service\s+)?(banner|header|version|fingerprint)",
            r"(?i)(service|server|application)\s+(banner|header|version)\s+(grab|collect|extract|captur)",
            r"(?i)(fingerprint|identif)\w*\s+(service|server|os|application)\s+(via|through|using)\s+(banner|header|response)",
        ],
        "severity": "high",
        "description": "Collecting service banners for fingerprinting targets",
    },
}


@dataclass
class ProbingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_ref: str = ""
    probing_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[ProbingEvent] = field(default_factory=list)


@dataclass
class ProbingChain:
    agent: str = ""
    steps: list[ProbingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    probing_score: float = 0.0


@dataclass
class NetworkProbingReport:
    total_events: int = 0
    probing_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    probing_chains: list[ProbingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(port.scan|service.discover|dns.enumerat|network.map|"
    r"vuln.scan|banner.grab|nmap|masscan|nessus|openvas|nikto|"
    r"traceroute|ping.sweep|zone.transfer)\b"
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


def _detect_chains(events: list[dict]) -> list[ProbingChain]:
    agent_events: dict[str, list[ProbingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            pe = ProbingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                probing_type=str(ev.get("probing_type", "")),
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ProbingChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                probing_score=round(score, 2),
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


def analyze_network_probing(events_or_dir: str | Path | list[dict]) -> NetworkProbingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> NetworkProbingReport:
    report = NetworkProbingReport(total_events=len(events))
    cat_events: dict[str, list[ProbingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.probing_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ProbingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                probing_type=str(ev.get("probing_type", "")),
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
    report.probing_chains = _detect_chains(events)
    return report


def format_text(report: NetworkProbingReport) -> str:
    lines = [
        "Network Probing Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Probing events: {report.probing_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.probing_chains:
        lines.append("")
        lines.append("Probing chains:")
        for c in report.probing_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.probing_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: NetworkProbingReport) -> str:
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
    for chain in data.get("probing_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
