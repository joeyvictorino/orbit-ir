"""Self-replicating agent (worm) detection for incident reconstruction.

Detects patterns where agents replicate, clone, or propagate themselves
across systems or spawn unauthorized copies:
- self_replication: agent copying/cloning itself to new hosts or environments
- spawn_flood: agent creating excessive child processes or agent instances
- payload_propagation: agent distributing malicious payloads to other agents
- lateral_spread: agent systematically spreading across available targets
- persistence_install: agent installing persistent copies or scheduled tasks
- polymorphic_mutation: agent modifying its own code/behavior to evade detection
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "self_replication": {
        "patterns": [
            r"(?i)(agent|process|instance)\s+(clon|copy|replicat|duplicat|reproduc)\w*\s+(itself|self|to|onto|across)",
            r"(?i)(self.replicat|auto.propagat|self.copy|self.clon)\w*\s+(detect|found|observ|trigger)",
            r"(?i)(clon|copy|replicat|duplicat)\w*\s+(agent|instance|process)\s+(to|onto|across|into)\s+(new|other|remote|additional)",
            r"(?i)(unauthoriz|unexpect|anomal)\w*\s+(replicat|clon|copy|spawn)\w*\s+(of|by)\s+(agent|process|instance)",
        ],
        "severity": "critical",
        "description": "Agent copying or cloning itself to new hosts or environments",
    },
    "spawn_flood": {
        "patterns": [
            r"(?i)(spawn|fork|creat|launch)\w*\s+(excessive|flood|burst|mass|rapid)\s+(child|sub|worker|instance|process|agent)",
            r"(?i)(excessive|abnormal|unusual)\s+(spawn|fork|process|instance|agent)\s+(count|rate|volume|creation)",
            r"(?i)(process|agent|instance)\s+(bomb|flood|storm|avalanche|explosion)\w*\s+(detect|observ|trigger)",
            r"(?i)(runaway|uncontroll|recursive)\s+(spawn|fork|creation|replication)\s+(of|by)\s+(agent|process|instance)",
        ],
        "severity": "high",
        "description": "Agent creating excessive child processes or agent instances",
    },
    "payload_propagation": {
        "patterns": [
            r"(?i)(distribut|propagat|spread|disseminat)\w*\s+(malicious|hostile|rogue|compromis)\w*\s+(payload|code|script|binary|agent)",
            r"(?i)(malicious|hostile|rogue)\s+(payload|code|script)\s+(distribut|propagat|spread|push)\w*\s+(to|across|among)",
            r"(?i)(inject|deploy|push|install)\w*\s+(payload|code|script|binary)\s+(to|into|across|onto)\s+(other|remote|target|peer)\s+(agent|host|node|system)",
            r"(?i)(worm|virus|malware)\w*\s+(payload|component|module)\s+(distribut|propagat|deliver|drop)\w*",
        ],
        "severity": "critical",
        "description": "Agent distributing malicious payloads to other agents",
    },
    "lateral_spread": {
        "patterns": [
            r"(?i)(systematic|sequential|automated)\w*\s+(spread|propagat|infect|compromis)\w*\s+(across|through|to)\s+(host|node|agent|system|target)",
            r"(?i)(lateral|horizontal)\s+(spread|propagat|movement|infect)\w*\s+(across|through|to)\s+(network|host|agent|system)",
            r"(?i)(infect|compromis|spread.to)\w*\s+(adjacent|neighbor|connected|reachable)\s+(host|node|agent|system|target)",
            r"(?i)(worm.like|worm.behavior|autonomous.spread)\w*\s+(detect|observ|pattern|across)",
        ],
        "severity": "critical",
        "description": "Agent systematically spreading across available targets",
    },
    "persistence_install": {
        "patterns": [
            r"(?i)(install|creat|register|add)\w*\s+(persistent|scheduled|startup|boot|cron|autorun)\s+(copy|instance|task|job|entry)",
            r"(?i)(persistent|scheduled|autorun)\s+(agent|process|task|copy|instance)\s+(install|creat|register|deploy)\w*\s+(on|at|in|across)",
            r"(?i)(cron|systemd|init\.d|launchd|registry|autostart)\s+(entry|job|service|task)\s+(creat|install|register|add)\w*\s+(for|by)\s+(agent|worm|malware|process)",
            r"(?i)(surviv|persist|maintain)\w*\s+(across|through|after)\s+(reboot|restart|shutdown|cleanup)\s+(via|by|using)\s+(scheduled|cron|startup|autorun)",
        ],
        "severity": "high",
        "description": "Agent installing persistent copies or scheduled tasks",
    },
    "polymorphic_mutation": {
        "patterns": [
            r"(?i)(modif|mutat|alter|transform)\w*\s+(own|self|its)\s+(code|behavior|signature|payload|binary)",
            r"(?i)(polymorphic|metamorphic|self.modify)\w*\s+(behavior|code|variant|mutation|evasion)\s+(detect|observ|found)",
            r"(?i)(code|behavior|signature)\s+(mutation|modification|transformation|morphing)\w*\s+(detect|observ|evad|bypass)\w*\s+(detection|analysis|scan)",
            r"(?i)(evad|bypass|avoid)\w*\s+(detection|analysis|signature|scan)\w*\s+(via|by|through|using)\s+(mutation|modification|polymorphi|metamorphi)",
        ],
        "severity": "high",
        "description": "Agent modifying its own code or behavior to evade detection",
    },
}


@dataclass
class WormEvent:
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
    events: list[WormEvent] = field(default_factory=list)


@dataclass
class WormChain:
    agent: str = ""
    steps: list[WormEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class WormDetectReport:
    total_events: int = 0
    worm_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    worm_chains: list[WormChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(self.replicat|auto.propagat|clone.agent|copy.agent|"
    r"spawn.flood|process.bomb|fork.bomb|payload.propagat|"
    r"worm.spread|lateral.spread|worm.like|autonomous.spread|"
    r"persist.install|cron.job|autorun|scheduled.task|"
    r"polymorphic|metamorphic|self.modify|code.mutation)\b"
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


def _detect_chains(events: list[dict]) -> list[WormChain]:
    from collections import defaultdict

    agent_events: dict[str, list[WormEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            we = WormEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(we)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(WormChain(
                agent=agent,
                steps=sevents[:10],
                techniques_used=techniques,
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


def analyze_worm_detection(events_or_dir: str | Path | list[dict]) -> WormDetectReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> WormDetectReport:
    report = WormDetectReport(total_events=len(events))

    cat_events: dict[str, list[WormEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.worm_events += 1
        for cat, technique in matches:
            e = WormEvent(
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
    report.worm_chains = _detect_chains(events)

    return report


def format_text(report: WormDetectReport) -> str:
    lines = [
        "Worm Detection Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Worm events: {report.worm_events}",
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

    if report.worm_chains:
        lines.append("")
        lines.append("Worm chains:")
        for c in report.worm_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: WormDetectReport) -> str:
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
    for chain in data.get("worm_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
