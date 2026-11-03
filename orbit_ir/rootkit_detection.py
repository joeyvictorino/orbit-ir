"""Rootkit detection pattern analysis for agent incident reconstruction.

Detects patterns where agents deploy or use rootkit-like capabilities:
- kernel_module_load: loading unauthorized kernel modules or drivers
- process_hiding: hiding processes from system monitoring tools
- file_hiding: concealing files or directories from filesystem listings
- network_hiding: hiding network connections or traffic from monitoring
- log_tampering_rootkit: modifying or deleting system logs to cover tracks
- persistence_mechanism: installing persistent backdoor mechanisms
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "kernel_module_load": {
        "patterns": [
            r"(?i)(kernel|kmod)\s+(module|driver)\s+(load|insert|inject|install)",
            r"(?i)(load|insert|inject|install)\w*\s+(kernel|kmod|lkm)\s+(module|driver|object)",
            r"(?i)(insmod|modprobe|rmmod)\s+(unauthor|malicious|unknown|suspicious|rogue)",
            r"(?i)(rootkit|malicious)\s+(kernel|kmod)\s+(module|driver|extension|hook)",
        ],
        "severity": "critical",
        "description": "Loading unauthorized kernel modules or drivers",
    },
    "process_hiding": {
        "patterns": [
            r"(?i)(process|pid|proc)\s+(hid|conceal|cloak|mask|invisible|stealth)",
            r"(?i)(hid|conceal|cloak|mask)\w*\s+(process|pid|task|thread)\s+(from|in)\s+(monitor|listing|ps|top|task.manager)",
            r"(?i)(hook|intercept|patch)\w*\s+(getdents|readdir|proc.filesystem|process.list)",
            r"(?i)(invisible|stealth|hidden|cloaked)\s+(process|daemon|service|agent)\s+(running|execut|active)",
        ],
        "severity": "critical",
        "description": "Hiding processes from system monitoring tools",
    },
    "file_hiding": {
        "patterns": [
            r"(?i)(file|directory|dir|folder)\s+(hid|conceal|cloak|mask|invisible|stealth)",
            r"(?i)(hid|conceal|cloak|mask)\w*\s+(file|director|folder|path)\s+(from|in)\s+(listing|ls|find|search|scan)",
            r"(?i)(hook|intercept|patch)\w*\s+(getdents|readdir|stat|open|access)\s+(to\s+)?(hid|conceal|filter)",
            r"(?i)(hidden|concealed|invisible)\s+(file|director|folder|artifact)\s+(on|in)\s+(disk|filesystem|storage)",
        ],
        "severity": "high",
        "description": "Concealing files or directories from filesystem listings",
    },
    "network_hiding": {
        "patterns": [
            r"(?i)(network|net|connection|socket|port)\s+(hid|conceal|cloak|mask|stealth|invisible)",
            r"(?i)(hid|conceal|cloak|mask)\w*\s+(network|connection|socket|port|traffic)\s+(from|in)\s+(monitor|netstat|ss|listing)",
            r"(?i)(hook|intercept|patch)\w*\s+(netstat|ss|tcp|udp|socket)\s+(to\s+)?(hid|conceal|filter)",
            r"(?i)(stealth|covert|hidden|invisible)\s+(network|connection|listener|backdoor|port)",
        ],
        "severity": "critical",
        "description": "Hiding network connections or traffic from monitoring",
    },
    "log_tampering_rootkit": {
        "patterns": [
            r"(?i)(log|audit|syslog|journal)\s+(tamper|modify|delet|erase|clear|wipe|scrub|purge)",
            r"(?i)(tamper|modify|delet|erase|clear|wipe)\w*\s+(with\s+)?(log|audit|syslog|journal|event.log|history)",
            r"(?i)(cover|hid|conceal|destroy)\w*\s+(track|trace|evidence|trail|footprint)\s+(in|from|by)\s+(log|audit|syslog)",
            r"(?i)(anti.forensic|counter.forensic)\w*\s+(log|audit|evidence)\s+(tamper|delet|modif|destroy)",
        ],
        "severity": "critical",
        "description": "Modifying or deleting system logs to cover tracks",
    },
    "persistence_mechanism": {
        "patterns": [
            r"(?i)(persistence|persist)\s+(mechanism|method|technique|install|backdoor|implant)",
            r"(?i)(install|creat|deploy|plant)\w*\s+(persistence|persistent)\s+(backdoor|implant|hook|mechanism|agent)",
            r"(?i)(boot|startup|init|cron|systemd|rc\.local)\s+(persist|backdoor|implant|hook|inject|tamper)",
            r"(?i)(surviv|persist)\w*\s+(reboot|restart|update|patch)\s+(via|through|using)\s+(rootkit|backdoor|hook|implant)",
        ],
        "severity": "critical",
        "description": "Installing persistent backdoor mechanisms",
    },
}


@dataclass
class RootkitEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_ref: str = ""
    rootkit_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[RootkitEvent] = field(default_factory=list)


@dataclass
class RootkitChain:
    agent: str = ""
    steps: list[RootkitEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class RootkitDetectionReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[RootkitChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(kernel.module|process.hid|file.hid|"
    r"network.hid|log.tamper|persistence|"
    r"rootkit|backdoor|lkm.inject|hook.syscall)\b"
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


def _detect_chains(events: list[dict]) -> list[RootkitChain]:
    agent_events: dict[str, list[RootkitEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            re_ = RootkitEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                rootkit_type=str(ev.get("rootkit_type", "")),
                raw=ev,
            )
            agent_events[agent].append(re_)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(RootkitChain(
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


def analyze_rootkit_detection(events_or_dir: str | Path | list[dict]) -> RootkitDetectionReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> RootkitDetectionReport:
    report = RootkitDetectionReport(total_events=len(events))
    cat_events: dict[str, list[RootkitEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = RootkitEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_ref=str(ev.get("target_ref", ev.get("target", ""))),
                rootkit_type=str(ev.get("rootkit_type", "")),
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


def format_text(report: RootkitDetectionReport) -> str:
    lines = [
        "Rootkit Detection Analysis",
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


def format_json(report: RootkitDetectionReport) -> str:
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
