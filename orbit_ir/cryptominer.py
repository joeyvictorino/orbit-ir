"""Cryptominer pattern detection for agent incident reconstruction.

Detects patterns where agents exhibit cryptomining behaviors:
- mining_pool_connection: connecting to known mining pools or stratum servers
- gpu_hijack: unauthorized GPU resource allocation for mining
- cpu_abuse: excessive CPU consumption patterns indicative of mining
- hash_computation: cryptographic hash computation at scale
- stratum_protocol: stratum mining protocol communication
- resource_throttle: throttling or hiding resource usage to avoid detection
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "mining_pool_connection": {
        "patterns": [
            r"(?i)(connect|join|register|communicat)\w*\s+(to\s+)?(mining\s+pool|pool\s+server|stratum\s+server|coin\s+pool)",
            r"(?i)(mining\s+pool|pool\s+server|stratum\s+server)\s+(connect|join|register|handshake|auth)",
            r"(?i)(pool\.mining|nanopool|f2pool|ethermine|slushpool|antpool|nicehash)\w*\s+(connect|endpoint|url|address)",
            r"(?i)(establish|initiat|open)\w*\s+(connection|link|session)\s+(to|with)\s+(mining|pool|stratum)",
        ],
        "severity": "critical",
        "description": "Connecting to known mining pools or stratum servers",
    },
    "gpu_hijack": {
        "patterns": [
            r"(?i)(gpu|cuda|opencl|graphics\s+card)\s+(hijack|commandeer|monopoliz|seiz|allocat|claim)\w*",
            r"(?i)(hijack|commandeer|monopoliz|seiz|unauthoriz)\w*\s+(the\s+)?(gpu|cuda|graphics|compute\s+unit)",
            r"(?i)(gpu|cuda)\s+(utiliz|usage|load|consumption)\s+(spike|surge|100|peak|max|full)",
            r"(?i)(unauthoriz|covert|hidden|stealth)\w*\s+(gpu|cuda|compute)\s+(usage|alloc|access|mining)",
        ],
        "severity": "critical",
        "description": "Unauthorized GPU resource allocation for mining operations",
    },
    "cpu_abuse": {
        "patterns": [
            r"(?i)(cpu|processor)\s+(abuse|exploit|monopoliz|overload|exhaust|saturat|max.out)",
            r"(?i)(abuse|exploit|monopoliz|overload|exhaust)\w*\s+(the\s+)?(cpu|processor|compute\s+resource)",
            r"(?i)(cpu|processor)\s+(usage|utiliz|load|consumption)\s+(spike|surge|100|peak|max|abnormal|suspicious)",
            r"(?i)(excessive|abnormal|suspicious|unexplain)\w*\s+(cpu|processor)\s+(usage|consumption|load|activity)",
        ],
        "severity": "high",
        "description": "Excessive CPU consumption patterns indicative of mining",
    },
    "hash_computation": {
        "patterns": [
            r"(?i)(hash|hashing)\s+(computation|calculat|generat|brute.forc|mining)\s+(at\s+scale|massiv|bulk|continuous)",
            r"(?i)(massiv|bulk|continuous|repeated)\s+(hash|hashing|sha256|scrypt|ethash|randomx)\s+(computation|calculat|operat)",
            r"(?i)(proof.of.work|pow|nonce)\s+(calculat|comput|search|brute|mining|generat)",
            r"(?i)(comput|calculat|generat)\w*\s+(hash|nonce|proof.of.work)\s+(for|toward|mining)",
        ],
        "severity": "high",
        "description": "Cryptographic hash computation at scale for mining",
    },
    "stratum_protocol": {
        "patterns": [
            r"(?i)(stratum|stratum\+tcp|stratum\+ssl)\s+(protocol|communicat|message|handshake|subscri|submit)",
            r"(?i)(mining\.subscribe|mining\.authorize|mining\.submit|mining\.notify)\b",
            r"(?i)(stratum|mining)\s+(protocol|wire)\s+(negotiat|handshake|initiat|message|packet)",
            r"(?i)(submit|send|transmit)\w*\s+(share|work|result)\s+(to|via|over)\s+(stratum|mining\s+pool|pool)",
        ],
        "severity": "critical",
        "description": "Stratum mining protocol communication patterns",
    },
    "resource_throttle": {
        "patterns": [
            r"(?i)(throttl|limit|cap|reduc)\w*\s+(mining|hash|computation|resource)\s+(to\s+)?(avoid|evade|prevent|hide)\w*\s+(detect|monitor|alert)",
            r"(?i)(hide|conceal|mask|disguise|camouflage)\w*\s+(mining|hash|crypto|resource)\s+(usage|activity|process|consumption)",
            r"(?i)(stealth|covert|hidden|low.profile)\s+(mining|miner|hash|crypto)\s+(mode|operat|config|process)",
            r"(?i)(evad|avoid|bypass|circumvent)\w*\s+(mining|crypto)\s+(detect|monitor|scan|alert)",
        ],
        "severity": "high",
        "description": "Throttling or hiding resource usage to avoid mining detection",
    },
}


@dataclass
class CryptominerEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    miner_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[CryptominerEvent] = field(default_factory=list)


@dataclass
class MinerChain:
    agent: str = ""
    steps: list[CryptominerEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class CryptominerReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[MinerChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(mining.pool|stratum|gpu.hijack|cpu.abuse|hash.comput|"
    r"resource.throttl|stealth.min|proof.of.work|nonce.search|"
    r"crypto.min|coin.min|pool.connect)\b"
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


def _detect_chains(events: list[dict]) -> list[MinerChain]:
    agent_events: dict[str, list[CryptominerEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ce = CryptominerEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                miner_type=str(ev.get("miner_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(MinerChain(
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


def analyze_cryptominer(events_or_dir: str | Path | list[dict]) -> CryptominerReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> CryptominerReport:
    report = CryptominerReport(total_events=len(events))
    cat_events: dict[str, list[CryptominerEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = CryptominerEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                miner_type=str(ev.get("miner_type", "")),
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


def format_text(report: CryptominerReport) -> str:
    lines = [
        "Cryptominer Analysis",
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


def format_json(report: CryptominerReport) -> str:
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
