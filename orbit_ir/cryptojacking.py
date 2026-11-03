"""Cryptojacking detection for agent incident reconstruction.

Detects patterns where agents attempt cryptocurrency mining or related abuse:
- mining_deployment: deploying cryptocurrency mining software
- resource_diversion: diverting compute resources to unauthorized mining
- pool_connection: connecting to mining pool servers
- hash_computation: performing unauthorized hash computations
- wallet_injection: injecting cryptocurrency wallet addresses
- miner_concealment: hiding mining activity from monitoring
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "mining_deployment": {
        "patterns": [
            r"(?i)(deploy|install|download|execut)\w*\s+(crypto\s*)?min(er|ing)\s*(software|binary|process|tool|payload)",
            r"(?i)(crypto\s*)?min(er|ing)\s+(deploy|install|download|binary|execut|launch|start)",
            r"(?i)(xmrig|cgminer|bfgminer|ethminer|cpuminer|nicehash)\s*(deploy|install|detect|found|running)",
            r"(?i)(deploy|install|drop)\w*\s+(coin\s*)?min(er|ing)\s+(on|to|across|into)\s+(host|server|container|node)",
        ],
        "severity": "critical",
        "description": "Deploying cryptocurrency mining software on compromised systems",
    },
    "resource_diversion": {
        "patterns": [
            r"(?i)(divert|redirect|hijack|steal|siphon)\w*\s+(compute|cpu|gpu|resource|processing)\s*(power|capacity|cycle|time)?",
            r"(?i)(compute|cpu|gpu|resource)\s+(diversion|hijack|theft|abuse|misuse|unauthorized)\w*\s*(for\s+)?(min|crypto|coin)",
            r"(?i)(unauthorized|illicit|covert)\s+(use|usage|consumption)\s+(of\s+)?(compute|cpu|gpu|resource)",
            r"(?i)(resource|cpu|gpu)\s+(spike|surge|anomal|exhaust)\w*\s+(due\s+to|caused\s+by|from)\s+(min|crypto)",
        ],
        "severity": "critical",
        "description": "Diverting compute resources to unauthorized mining operations",
    },
    "pool_connection": {
        "patterns": [
            r"(?i)(connect|communicat|reach)\w*\s+(to\s+)?(mining|miner|stratum)\s+(pool|server|proxy|endpoint)",
            r"(?i)(mining|miner|stratum)\s+(pool|server|proxy)\s+(connect|communicat|endpoint|address|url)",
            r"(?i)(stratum|stratum\+tcp|stratum\+ssl)://.+",
            r"(?i)(outbound|egress)\s+(connect|traffic|communicat)\w*\s+(to\s+)?(known\s+)?(mining|crypto|pool)\s+(pool|server|endpoint|domain)",
        ],
        "severity": "high",
        "description": "Connecting to mining pool servers for coordinated mining",
    },
    "hash_computation": {
        "patterns": [
            r"(?i)(unauthorized|illicit|covert|suspicious)\s+(hash|hashing|proof.of.work|pow)\s+(comput|calculat|operat|process)",
            r"(?i)(hash|hashing)\s+(comput|calculat|rate|power)\s+(spike|surge|anomal|unauthorized|unexpect)",
            r"(?i)(perform|execut|run)\w*\s+(crypto\w*\s+)?(hash|hashing|proof.of.work)\s+(comput|calculat|operat)",
            r"(?i)(sha256|scrypt|ethash|randomx|cryptonight)\s+(hash|comput|calculat|operat|workload)",
        ],
        "severity": "high",
        "description": "Performing unauthorized hash computations for mining",
    },
    "wallet_injection": {
        "patterns": [
            r"(?i)(inject|insert|embed|plant|configur)\w*\s+(crypto\w*\s+)?(wallet|address|payout)\s*(address|destination|config)",
            r"(?i)(wallet|crypto\w*\s+address)\s+(inject|insert|embed|replac|swap|modif)",
            r"(?i)(replac|swap|modif|chang)\w*\s+(wallet|payout|destination)\s+(address|config)",
            r"(?i)(hardcod|embed|plant)\w*\s+(wallet|bitcoin|ethereum|monero|crypto)\s+(address|key|id)",
        ],
        "severity": "high",
        "description": "Injecting cryptocurrency wallet addresses into configurations",
    },
    "miner_concealment": {
        "patterns": [
            r"(?i)(conceal|hide|mask|disguis|camouflage|cloak)\w*\s+(min(er|ing)|crypto\w*)\s*(process|activity|operat|software|binary)",
            r"(?i)(min(er|ing)|crypto\w*)\s+(conceal|hidden|mask|disguis|stealth|covert)\w*\s*(mode|operat|process)?",
            r"(?i)(renam|disguis|obfuscat)\w*\s+(min(er|ing)|crypto)\s+(process|binary|executable|service)\s+(to\s+)?(avoid|evade|bypass)\s+(detect|monitor)",
            r"(?i)(throttl|limit|reduc)\w*\s+(min(er|ing)|crypto)\s+(when|during|if)\s+(monitor|admin|user|detect)",
        ],
        "severity": "critical",
        "description": "Hiding mining activity from monitoring and detection systems",
    },
}


@dataclass
class CryptojackingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    policy_ref: str = ""
    violation_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[CryptojackingEvent] = field(default_factory=list)


@dataclass
class CryptojackingChain:
    agent: str = ""
    steps: list[CryptojackingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class CryptojackingReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[CryptojackingChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(crypto.?mining|coin.?mining|resource.?diversion|pool.?connect|"
    r"hash.?comput|wallet.?inject|miner.?conceal|stratum|xmrig|cryptonight)\b"
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


def _detect_chains(events: list[dict]) -> list[CryptojackingChain]:
    agent_events: dict[str, list[CryptojackingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = CryptojackingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(CryptojackingChain(
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


def analyze_cryptojacking(events_or_dir: str | Path | list[dict]) -> CryptojackingReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> CryptojackingReport:
    report = CryptojackingReport(total_events=len(events))
    cat_events: dict[str, list[CryptojackingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = CryptojackingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
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


def format_text(report: CryptojackingReport) -> str:
    lines = [
        "Cryptojacking Analysis",
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


def format_json(report: CryptojackingReport) -> str:
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
