"""Backdoor installation detection for agent incident reconstruction.

Detects patterns where agents install persistent backdoors:
- reverse_shell: establishing reverse shell connections for remote access
- web_shell: deploying web-based command execution interfaces
- cron_persistence: using scheduled tasks for persistent access
- ssh_key_injection: injecting unauthorized SSH keys for access
- rootkit_deployment: installing rootkits to hide malicious presence
- service_hijacking: hijacking system services for persistent access
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "reverse_shell": {
        "patterns": [
            r"(?i)(establish|creat|open|initiat|spawn)\w*\s+(reverse|back.?connect)\s+(shell|connection|tunnel|channel)",
            r"(?i)(reverse|back.?connect)\s+(shell|connection|tunnel)\s+(establish|creat|open|detect|found|active)",
            r"(?i)(netcat|ncat|nc|socat|bash\s+-i)\s+(reverse|connect.?back|listen|bind)\w*\s*(shell|port|address)?",
            r"(?i)(callback|phone.?home|beacon)\w*\s+(shell|connection|channel)\s+(to\s+)?(remote|external|attacker|c2)",
        ],
        "severity": "critical",
        "description": "Establishing reverse shell connections for remote access",
    },
    "web_shell": {
        "patterns": [
            r"(?i)(deploy|install|upload|drop|plant)\w*\s+(web\s*shell|backdoor\s+script|command\s+shell|php\s+shell)",
            r"(?i)(web\s*shell|command\s+shell)\s+(deploy|install|upload|detect|found|plant|drop)",
            r"(?i)(php|jsp|asp|python)\s+(web\s*shell|backdoor|command\s+execut)\s+(deploy|upload|detect|found)",
            r"(?i)(c99|r57|b374k|weevely|china\s*chopper)\s+(shell|backdoor|detect|found|deploy)",
        ],
        "severity": "critical",
        "description": "Deploying web-based command execution interfaces",
    },
    "cron_persistence": {
        "patterns": [
            r"(?i)(add|creat|install|modif|inject)\w*\s+(cron|crontab|scheduled|at)\s+(job|task|entry|persistence|backdoor)",
            r"(?i)(cron|crontab|scheduled)\s+(job|task|entry)\s+(add|creat|install|modif|inject|backdoor|malicious)",
            r"(?i)(persist|maintain)\w*\s+(access|presence|foothold)\s+(via|through|using)\s+(cron|crontab|scheduled|systemd.timer)",
            r"(?i)(malicious|unauthorized|suspicious)\s+(cron|crontab|scheduled)\s+(job|task|entry|script)",
        ],
        "severity": "high",
        "description": "Using scheduled tasks for persistent backdoor access",
    },
    "ssh_key_injection": {
        "patterns": [
            r"(?i)(inject|add|insert|plant|append)\w*\s+(unauthorized|malicious|rogue|attacker)?\s*(ssh|public)\s+(key|authorized.key)",
            r"(?i)(ssh|public)\s+(key|authorized.key)\s+(inject|add|insert|plant|append|unauthorized|malicious)",
            r"(?i)(modif|append|write)\w*\s+(to\s+)?authorized.keys\s+(file|for\s+)?(unauthorized|backdoor|persist)",
            r"(?i)(unauthorized|malicious|rogue)\s+(ssh|remote)\s+(access|key|login)\s+(inject|add|establish|detect)",
        ],
        "severity": "critical",
        "description": "Injecting unauthorized SSH keys for persistent access",
    },
    "rootkit_deployment": {
        "patterns": [
            r"(?i)(deploy|install|load|inject)\w*\s+(rootkit|kernel\s+module|lkm)\s*(backdoor|malicious|stealth)?",
            r"(?i)(rootkit|kernel\s+module\s+backdoor)\s+(deploy|install|load|detect|found|active|hidden)",
            r"(?i)(hide|conceal|cloak)\w*\s+(process|file|connection|port)\s+(using|via|with)\s+(rootkit|kernel\s+module|hook)",
            r"(?i)(system\s+call|syscall)\s+(hook|intercept|modif|patch)\w*\s+(for|to)\s+(hide|conceal|backdoor)",
        ],
        "severity": "critical",
        "description": "Installing rootkits to hide malicious presence on systems",
    },
    "service_hijacking": {
        "patterns": [
            r"(?i)(hijack|compromis|modif|replac|trojaniz)\w*\s+(system|systemd|init|daemon)\s+(service|unit|script|binary)",
            r"(?i)(system|systemd|init)\s+(service|unit|script)\s+(hijack|compromis|modif|replac|trojaniz|backdoor)",
            r"(?i)(replac|swap|modif|patch)\w*\s+(legitimate|original|system)\s+(service|binary|daemon)\s+(with\s+)?(backdoor|malicious|trojan)",
            r"(?i)(persist|maintain)\w*\s+(access|backdoor|presence)\s+(via|through|by)\s+(service|systemd|daemon|init)\s+(hijack|modif|creat)",
        ],
        "severity": "critical",
        "description": "Hijacking system services for persistent backdoor access",
    },
}


@dataclass
class BackdoorEvent:
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
    events: list[BackdoorEvent] = field(default_factory=list)


@dataclass
class BackdoorChain:
    agent: str = ""
    steps: list[BackdoorEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class BackdoorInstallReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[BackdoorChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(reverse.?shell|web.?shell|cron.?persist|ssh.?key.?inject|"
    r"rootkit|service.?hijack|backdoor|trojan|c99|r57|netcat|authorized.keys)\b"
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


def _detect_chains(events: list[dict]) -> list[BackdoorChain]:
    agent_events: dict[str, list[BackdoorEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = BackdoorEvent(
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
            chains.append(BackdoorChain(
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


def analyze_backdoor_install(events_or_dir: str | Path | list[dict]) -> BackdoorInstallReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> BackdoorInstallReport:
    report = BackdoorInstallReport(total_events=len(events))
    cat_events: dict[str, list[BackdoorEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = BackdoorEvent(
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


def format_text(report: BackdoorInstallReport) -> str:
    lines = [
        "Backdoor Installation Analysis",
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


def format_json(report: BackdoorInstallReport) -> str:
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
