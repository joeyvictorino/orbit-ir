"""Supply chain attack detection for agent incident reconstruction.

Detects patterns where agents compromise the software supply chain:
- dependency_poisoning: injecting malicious code into dependencies
- build_tampering: modifying build processes or artifacts
- package_substitution: replacing legitimate packages with malicious ones
- update_hijacking: intercepting or corrupting software updates
- artifact_manipulation: tampering with compiled or packaged artifacts
- registry_compromise: attacking package registries or repositories
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "dependency_poisoning": {
        "patterns": [
            r"(?i)(dependency|package|library|module)\s+(poison|inject|tamper|compromise|infect|trojan)",
            r"(?i)(inject|insert|embed|implant)\w*\s+(malicious|hostile|rogue|backdoor)\s+(code|payload|script)\s+(in|into|within)\s+(depend|package|library|module)",
            r"(?i)(poison|corrupt|tamper)\w*\s+(dependency|package|library|module)\s+(tree|graph|chain|resolut)",
            r"(?i)(malicious|rogue|hostile)\s+(dependency|package|library|module)\s+(inject|introduc|install|add)",
        ],
        "severity": "critical",
        "description": "Injecting malicious code into dependencies",
    },
    "build_tampering": {
        "patterns": [
            r"(?i)(build)\s+(tamper|manipulat|compromise|corrupt|inject|modify|alter|sabotag)",
            r"(?i)(tamper|manipulat|compromise|modify)\w*\s+(build)\s+(process|pipeline|system|script|config|step|stage)",
            r"(?i)(inject|insert|embed)\w*\s+(malicious|hostile|rogue|backdoor)\s+(code|step|command)\s+(in|into)\s+(build|ci|cd|pipeline)",
            r"(?i)(build|compilation|linking)\s+(process|artifact|output)\s+(tamper|manipulat|corrupt|compromise|alter)",
        ],
        "severity": "critical",
        "description": "Modifying build processes or artifacts",
    },
    "package_substitution": {
        "patterns": [
            r"(?i)(package|dependency|library)\s+(substitut|replac|swap|spoof|impersonat|typosquat)",
            r"(?i)(substitut|replac|swap)\w*\s+(legitimate|genuine|authentic|official)\s+(package|dependency|library|module)\s+(with)\s+(malicious|rogue|hostile|fake)",
            r"(?i)(typosquat|name.?squat|combosquat)\w*\s+(package|dependency|library|attack)",
            r"(?i)(fake|counterfeit|forged|imitat)\s+(package|dependency|library|module)\s+(upload|publish|register|distribut)",
        ],
        "severity": "critical",
        "description": "Replacing legitimate packages with malicious ones",
    },
    "update_hijacking": {
        "patterns": [
            r"(?i)(update|upgrade|patch)\s+(hijack|intercept|redirect|tamper|compromise|corrupt|manipulat)",
            r"(?i)(hijack|intercept|redirect|tamper)\w*\s+(software|package|system|firmware)\s+(update|upgrade|patch)",
            r"(?i)(man.in.the.middle|mitm)\s+(update|upgrade|patch)\s+(attack|intercept|tamper|hijack)",
            r"(?i)(update|upgrade)\s+(channel|mechanism|server|mirror)\s+(compromise|hijack|tamper|manipulat|spoof)",
        ],
        "severity": "critical",
        "description": "Intercepting or corrupting software updates",
    },
    "artifact_manipulation": {
        "patterns": [
            r"(?i)(artifact|binary|executable|container.image)\s+(manipulat|tamper|modify|corrupt|inject|alter|replace)",
            r"(?i)(tamper|manipulat|modify|corrupt)\w*\s+(compiled|built|packaged|released)\s+(artifact|binary|executable|image)",
            r"(?i)(inject|embed|implant)\w*\s+(backdoor|malware|payload|trojan)\s+(in|into)\s+(artifact|binary|executable|image|container)",
            r"(?i)(signature|hash|checksum|digest)\s+(bypass|forge|spoof|manipulat|tamper|strip|remove)",
        ],
        "severity": "high",
        "description": "Tampering with compiled or packaged artifacts",
    },
    "registry_compromise": {
        "patterns": [
            r"(?i)(registry|repository|repo)\s+(compromise|attack|breach|infiltrat|hack|tamper|manipulat)",
            r"(?i)(compromise|infiltrat|hack|breach)\w*\s+(package|container|docker|npm|pypi|maven)\s+(registry|repository|repo|index)",
            r"(?i)(upload|publish|push)\w*\s+(malicious|rogue|hostile|backdoor)\s+(package|image|artifact)\s+(to\s+)?(registry|repository|repo)",
            r"(?i)(registry|repository)\s+(credential|token|key)\s+(steal|compromise|leak|exfiltrat|abuse)",
        ],
        "severity": "critical",
        "description": "Attacking package registries or repositories",
    },
}


@dataclass
class SupplyChainEvent:
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
    events: list[SupplyChainEvent] = field(default_factory=list)


@dataclass
class SupplyChainChain:
    agent: str = ""
    steps: list[SupplyChainEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class SupplyChainReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[SupplyChainChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(dependency.poison|build.tamper|package.substitut|"
    r"update.hijack|artifact.manipulat|registry.compromise|"
    r"typosquat|name.squat|supply.chain)\b"
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


def _detect_chains(events: list[dict]) -> list[SupplyChainChain]:
    agent_events: dict[str, list[SupplyChainEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = SupplyChainEvent(
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
            chains.append(SupplyChainChain(
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


def analyze_supply_chain_attacks(events_or_dir: str | Path | list[dict]) -> SupplyChainReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> SupplyChainReport:
    report = SupplyChainReport(total_events=len(events))
    cat_events: dict[str, list[SupplyChainEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = SupplyChainEvent(
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


def format_text(report: SupplyChainReport) -> str:
    lines = [
        "Supply Chain Attack Analysis",
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


def format_json(report: SupplyChainReport) -> str:
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
