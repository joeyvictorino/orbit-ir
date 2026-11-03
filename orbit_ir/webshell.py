"""Web shell deployment and usage detection for agent incident reconstruction.

Detects web shell deployment and remote command execution patterns:
- shell_upload: uploading web shell files to servers
- command_execution: executing system commands through web interfaces
- backdoor_install: installing persistent backdoor access via web
- file_manipulation: reading/writing sensitive files through web shells
- privilege_escalation: using web shells to escalate privileges
- defense_evasion: obfuscating or hiding web shell presence
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "shell_upload": {
        "patterns": [
            r"(?i)(upload|deploy|install|drop|place|inject)\w*\s+(web\s*shell|shell\s*file|backdoor\s*script|php\s*shell|jsp\s*shell|asp\s*shell)",
            r"(?i)(web\s*shell|shell\s*file|backdoor\s*script)\s+(upload|deploy|install|drop|place|inject|write|creat)",
            r"(?i)(write|creat|place|drop)\w*\s+(malicious|backdoor|shell)\s+(file|script|page)\s+(to|in|on|at)\s+(web|server|document\s*root|www)",
            r"(?i)(PUT|POST)\s+(request|method)\s+(upload|deploy|install)\w*\s+(shell|backdoor|webshell)",
        ],
        "severity": "critical",
        "description": "Uploading web shell files to web servers",
    },
    "command_execution": {
        "patterns": [
            r"(?i)(execut|run|invoke|launch|spawn)\w*\s+(system|os|shell|cmd|command|bash|powershell)\w*\s+(via|through|using|from)\s+(web|http|browser|url|request)",
            r"(?i)(web\s*shell|backdoor|remote)\s+(execut|run|invoke|command|cmd)\w*",
            r"(?i)(cmd|command|system|exec|passthru|shell_exec|eval)\s*\(.*\)\s*(via|through|from)\s*(web|http)",
            r"(?i)(remote\s+command|remote\s+code)\s+(execut|run|invoke|inject)\w*\s+(through|via|using)\s+(web|http|shell|backdoor)",
        ],
        "severity": "critical",
        "description": "Executing system commands through web interfaces",
    },
    "backdoor_install": {
        "patterns": [
            r"(?i)(install|establish|create|set\s*up|plant|embed)\w*\s+(persistent|hidden|covert|stealthy)\s+(backdoor|access|shell|entry\s*point|web\s*shell)",
            r"(?i)(backdoor|persistent\s+access|hidden\s+entry)\s+(install|establish|creat|set\s*up|configur|embed)\w*\s+(on|in|via|through)\s+(web|server|http)",
            r"(?i)(modify|alter|inject)\w*\s+(existing|legitimate|normal)\s+(page|file|script|handler)\s+(to\s+)?(include|add|embed)\s+(backdoor|shell|reverse)",
            r"(?i)(hidden|covert|stealth|obfuscat)\w*\s+(web\s*shell|backdoor|access\s*point|entry\s*point)\s+(install|deploy|plant|embed)",
            r"(?i)(install|establish|create|plant|embed)\w*\s+persistent\s+\w+\s+(backdoor|access|shell|web\s*shell)",
        ],
        "severity": "critical",
        "description": "Installing persistent backdoor access via web interfaces",
    },
    "file_manipulation": {
        "patterns": [
            r"(?i)(read|access|exfiltrat|download|view|dump)\w*\s+(sensitive|config|password|credential|secret|key|database)\s+(file|data|content)\s+(via|through|using)\s+(web\s*shell|backdoor|shell)",
            r"(?i)(web\s*shell|backdoor|shell)\s+(read|access|exfiltrat|dump|view|download)\w*\s+(sensitive|config|password|credential|/etc/|/var/|\.env|\.conf)",
            r"(?i)(write|modify|overwrite|replace|tamper)\w*\s+(system|config|web|server)\s+(file|config|setting)\s+(via|through|using)\s+(web\s*shell|backdoor|shell)",
            r"(?i)(file\s+browser|directory\s+listing|file\s+manager)\s+(through|via|in)\s+(web\s*shell|backdoor)",
        ],
        "severity": "high",
        "description": "Reading or writing sensitive files through web shells",
    },
    "privilege_escalation": {
        "patterns": [
            r"(?i)(escalat|elevat|gain|obtain)\w*\s+(privilege|permission|access|root|admin|superuser)\s+(via|through|using|from)\s+(web\s*shell|backdoor|shell)",
            r"(?i)(web\s*shell|backdoor|shell)\s+(escalat|elevat|gain)\w*\s+(privilege|permission|root|admin|sudo)",
            r"(?i)(sudo|su|setuid|suid|sgid)\s+(execut|run|command|exploit)\w*\s+(via|through|from)\s+(web\s*shell|backdoor|remote)",
            r"(?i)(exploit|abuse|leverag)\w*\s+(web\s*shell|backdoor)\s+(for|to)\s+(privilege|root|admin|escal)",
            r"(?i)(escalat|elevat)\w*\s+privilege\w*\s+to\s+\w+\s+(through|via|using)\s+(web\s*shell|backdoor|shell)",
        ],
        "severity": "critical",
        "description": "Using web shells to escalate privileges on compromised systems",
    },
    "defense_evasion": {
        "patterns": [
            r"(?i)(obfuscat|encod|encrypt|hide|conceal|disguise|camouflage)\w*\s+(web\s*shell|backdoor|shell|payload|script)",
            r"(?i)(web\s*shell|backdoor|shell)\s+(obfuscat|encod|encrypt|hide|conceal|disguise|camouflage)\w*",
            r"(?i)(rename|move|bury|nest)\w*\s+(web\s*shell|backdoor|shell)\s+(to\s+)?(avoid|evade|bypass)\s+(detect|scan|antivirus|monitor)",
            r"(?i)(anti[-.]?forensic|log\s+clear|log\s+tamper|log\s+delet|cover\s+track)\w*\s+(for|after|following)\s+(web\s*shell|backdoor|shell|intrusion)",
        ],
        "severity": "high",
        "description": "Obfuscating or hiding web shell presence to avoid detection",
    },
}


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(web.?shell|shell.upload|backdoor.install|"
    r"command.execut|remote.shell|file.manipulat|"
    r"privilege.escalat|defense.evasion|"
    r"php.shell|jsp.shell|asp.shell|reverse.shell)\b"
)


@dataclass
class WebshellEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_url: str = ""
    shell_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[WebshellEvent] = field(default_factory=list)


@dataclass
class WebshellChain:
    agent: str = ""
    steps: list[WebshellEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    webshell_score: float = 0.0


@dataclass
class WebshellReport:
    total_events: int = 0
    webshell_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    webshell_chains: list[WebshellChain] = field(default_factory=list)


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


def _detect_chains(events: list[dict]) -> list[WebshellChain]:
    agent_events: dict[str, list[WebshellEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            we = WebshellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_url=str(ev.get("target_url", ev.get("url", ""))),
                shell_type=str(ev.get("shell_type", "")),
                raw=ev,
            )
            agent_events[agent].append(we)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(WebshellChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                webshell_score=round(score, 2),
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


def analyze_webshell(events_or_dir: str | Path | list[dict]) -> WebshellReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> WebshellReport:
    report = WebshellReport(total_events=len(events))
    cat_events: dict[str, list[WebshellEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.webshell_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = WebshellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_url=str(ev.get("target_url", ev.get("url", ""))),
                shell_type=str(ev.get("shell_type", "")),
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
    report.webshell_chains = _detect_chains(events)
    return report


def format_text(report: WebshellReport) -> str:
    lines = [
        "Web Shell Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Web shell events: {report.webshell_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.webshell_chains:
        lines.append("")
        lines.append("Web shell chains:")
        for c in report.webshell_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.webshell_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: WebshellReport) -> str:
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
    for chain in data.get("webshell_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
