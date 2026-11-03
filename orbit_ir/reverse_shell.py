"""Reverse shell detection for agent incident reconstruction.

Detects patterns where agents establish reverse shell connections:
- outbound_connect: suspicious outbound connection patterns to external hosts
- shell_spawn: spawning shell processes from unexpected parent processes
- pipe_redirect: redirecting stdin/stdout/stderr through network connections
- encoded_payload: using encoded or obfuscated payloads for shell access
- bind_shell: binding a shell to a listening port for inbound connections
- tunneled_shell: tunneling shell connections through legitimate protocols
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "outbound_connect": {
        "patterns": [
            r"(?i)(reverse|outbound|callback|connect.?back)\s+(shell|connection|channel|socket|tcp|session)",
            r"(?i)(establish|creat|open|initiat)\w*\s+(outbound|reverse|callback)\s+(connection|socket|channel|shell)",
            r"(?i)(connect|dial|reach)\w*\s+(back|out)\s+(to|toward)\s+(c2|command|control|attacker|external|remote)",
            r"(?i)(suspicious|anomalous|unexpected)\s+(outbound|egress|external)\s+(connection|traffic|socket|request)",
        ],
        "severity": "critical",
        "description": "Suspicious outbound connection patterns to external command-and-control hosts",
    },
    "shell_spawn": {
        "patterns": [
            r"(?i)(spawn|launch|exec|fork|start|creat)\w*\s+(shell|bash|sh|cmd|powershell|zsh|command.?line)",
            r"(?i)(shell|bash|sh|cmd|powershell)\s+(spawn|launch|exec|fork|start|creat)\w*\s+(from|by|via)",
            r"(?i)(unexpected|suspicious|anomalous|unauthorized)\s+(shell|bash|cmd|powershell)\s+(spawn|process|execution|launch)",
            r"(?i)(child.?process|subprocess|fork)\w*\s+(shell|bash|sh|cmd|powershell|command.?interpreter)",
        ],
        "severity": "critical",
        "description": "Spawning shell processes from unexpected parent processes",
    },
    "pipe_redirect": {
        "patterns": [
            r"(?i)(pipe|redirect|dup2|dup)\w*\s+(stdin|stdout|stderr|fd|file.?descriptor)\s+(to|into|through)\s+(socket|network|connection|tcp)",
            r"(?i)(stdin|stdout|stderr)\s+(redirect|pipe|forward|connect|dup)\w*\s+(to|into|through)\s+(socket|network|tcp|remote)",
            r"(?i)(socket|network|tcp|connection)\s+(pipe|redirect|forward)\w*\s+(stdin|stdout|stderr|io|input|output)",
            r"(?i)(fifo|named.?pipe|mkfifo)\s+(redirect|connect|forward|tunnel)\w*\s+(shell|command|bash|sh)",
        ],
        "severity": "critical",
        "description": "Redirecting standard I/O streams through network connections",
    },
    "encoded_payload": {
        "patterns": [
            r"(?i)(encoded|obfuscated|base64|hex|encrypted)\s+(payload|shell|command|script|reverse|backdoor)",
            r"(?i)(payload|shell|command|script)\s+(encoded|obfuscated|base64|encrypted|scrambled|packed)",
            r"(?i)(decode|deobfuscat|decrypt|unpack)\w*\s+(and\s+)?(execute|exec|run|eval|invoke)\w*\s+(payload|shell|command)",
            r"(?i)(base64|hex|xor|rot13)\s+(encod|decod|obfuscat)\w*\s+(reverse|shell|payload|backdoor|command)",
        ],
        "severity": "high",
        "description": "Using encoded or obfuscated payloads to establish shell access",
    },
    "bind_shell": {
        "patterns": [
            r"(?i)(bind|listen|bound)\s+(shell|port|socket)\s+(on|to|at)\s+(port|address|interface|\d+)",
            r"(?i)(shell|command.?line|bash|cmd)\s+(bind|listen|bound)\w*\s+(on|to|at)\s+(port|socket|address|\d+)",
            r"(?i)(open|creat|bind)\w*\s+(listening|inbound|server)\s+(socket|port|shell|backdoor)",
            r"(?i)(listener|server|daemon)\s+(shell|backdoor|command)\s+(bind|open|creat|start)",
        ],
        "severity": "critical",
        "description": "Binding a shell to a listening port for inbound attacker connections",
    },
    "tunneled_shell": {
        "patterns": [
            r"(?i)(tunnel|tunneling|encapsulat)\w*\s+(shell|reverse|command|backdoor)\s+(through|via|over|inside)\s+(http|https|dns|ssh|icmp|websocket)",
            r"(?i)(shell|reverse|command|backdoor)\s+(tunnel|tunneling|encapsulat)\w*\s+(through|via|over|inside)\s+(http|https|dns|ssh|icmp)",
            r"(?i)(http|https|dns|ssh|icmp|websocket)\s+(tunnel|covert|hidden)\s+(shell|channel|command|reverse)",
            r"(?i)(covert|hidden|stealth|encrypted)\s+(channel|tunnel|shell)\s+(via|through|over)\s+(http|dns|icmp|legitimate)",
        ],
        "severity": "high",
        "description": "Tunneling shell connections through legitimate protocols to evade detection",
    },
}


@dataclass
class ReverseShellEvent:
    timestamp: str = ""
    agent_id: str = ""
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
    events: list[ReverseShellEvent] = field(default_factory=list)


@dataclass
class ReverseShellChain:
    agent: str = ""
    steps: list[ReverseShellEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class ReverseShellReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[ReverseShellChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(reverse.shell|bind.shell|outbound.connect|shell.spawn|"
    r"pipe.redirect|encoded.payload|base64|tunneled.shell|"
    r"callback|connect.back|named.pipe|mkfifo|dup2|"
    r"netcat|ncat|socat|nc)\b"
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


def _detect_chains(events: list[dict]) -> list[ReverseShellChain]:
    agent_events: dict[str, list[ReverseShellEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            rse = ReverseShellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(rse)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ReverseShellChain(
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


def analyze_reverse_shells(events_or_dir: str | Path | list[dict]) -> ReverseShellReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> ReverseShellReport:
    report = ReverseShellReport(total_events=len(events))
    cat_events: dict[str, list[ReverseShellEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = ReverseShellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
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


def format_text(report: ReverseShellReport) -> str:
    lines = [
        "Reverse Shell Analysis",
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


def format_json(report: ReverseShellReport) -> str:
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
