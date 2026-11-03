"""Web shell deployment pattern detection for agent incident reconstruction.

Detects patterns where agents deploy or interact with web shells:
- webshell_upload: uploading web shell scripts to writable web directories
- webshell_execution: executing system commands through web shell interfaces
- webshell_obfuscation: obfuscated web shell code to evade detection
- reverse_shell: establishing reverse shell connections from web server
- file_manager_abuse: using web-based file managers for unauthorized access
- backdoor_persistence: planting persistent backdoor endpoints in web apps
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "webshell_upload": {
        "patterns": [
            r"(?i)(upload|deploy|drop|plant|write)\w*\s+(web\s*shell|shell\s+script|backdoor|payload)\s+(to|into|on)\s+(web|www|public|htdocs|uploads)",
            r"(?i)(web\s*shell|shell\s+file|\.php\s+shell|\.jsp\s+shell|\.asp\s+shell)\s+(upload|creat|deploy|drop|writ)",
            r"(?i)(c99|r57|b374k|weevely|wso|china\s*chopper|antsword)\s+(upload|deploy|detect|found)",
            r"(?i)(multipart|file\s+upload)\s+(exploit|bypass|abuse)\w*\s+(shell|backdoor|payload)",
        ],
        "severity": "critical",
        "description": "Uploading web shell scripts to writable web directories",
    },
    "webshell_execution": {
        "patterns": [
            r"(?i)(exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
            r"(?i)(web\s*shell|remote\s+shell|command\s+shell)\s+(exec|run|invok|trigger|activat)",
            r"(?i)(execute|run|invoke)\w*\s+(system|os|shell)\s+(command|cmd)\s+(via|through|using)\s+(web|http|url|php|jsp|asp)",
            r"(?i)(cmd|command)\s*[=&?]\s*['\"]?(whoami|id|uname|cat\s+/etc|ls\s+-|pwd|net\s+user)",
        ],
        "severity": "critical",
        "description": "Executing system commands through web shell interfaces",
    },
    "webshell_obfuscation": {
        "patterns": [
            r"(?i)(obfuscat|encod|encrypt|pack|compress)\w*\s+(web\s*shell|shell\s+code|backdoor|payload)",
            r"(?i)(base64_decode|eval|assert|preg_replace.*e)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            r"(?i)(gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(",
            r"(?i)(char|chr|fromCharCode|string\.concat)\s*\(\s*\d+.*\d+.*\d+",
        ],
        "severity": "high",
        "description": "Obfuscated web shell code to evade detection",
    },
    "reverse_shell": {
        "patterns": [
            r"(?i)(reverse|bind)\s+(shell|connect|tcp|callback)\s+(establish|creat|open|initiat|spawn)",
            r"(?i)(nc|netcat|ncat|socat)\s+(-e|-c|--exec|--sh-exec)\s+(bash|sh|cmd|powershell)",
            r"(?i)(bash\s+-i|python\s+-c.*socket|perl\s+-e.*socket|ruby\s+-rsocket)",
            r"(?i)(meterpreter|metasploit|cobalt\s*strike|implant)\s+(reverse|callback|beacon|connect)",
        ],
        "severity": "critical",
        "description": "Establishing reverse shell connections from web server",
    },
    "file_manager_abuse": {
        "patterns": [
            r"(?i)(file\s+manager|web\s+file\s+browser|elfinder|tinymce\s+file)\s+(exploit|abuse|unauthor|bypass)",
            r"(?i)(browse|list|read|download|modify)\w*\s+(server|system|config|sensitive)\s+files?\s+(via|through|using)\s+(web|http|file\s+manager)",
            r"(?i)(directory\s+traversal|path\s+traversal|\.\.\/|\.\.\\)\s+(via|in|through)\s+(file\s+manager|upload|web)",
            r"(?i)(unauthor|illegal|forbidden)\w*\s+(file|directory)\s+(access|read|write|list|browse)\s+(via|through)\s+(web|http)",
        ],
        "severity": "high",
        "description": "Using web-based file managers for unauthorized access",
    },
    "backdoor_persistence": {
        "patterns": [
            r"(?i)(plant|install|embed|inject)\w*\s+(backdoor|persistent|hidden)\s+(endpoint|route|handler|page|script)",
            r"(?i)(backdoor|hidden)\s+(endpoint|url|path|api|route|page)\s+(creat|add|register|plant|install)",
            r"(?i)(persist|maintain|keep)\w*\s+(access|backdoor|shell|foothold)\s+(via|through|using)\s+(web|http|endpoint|route)",
            r"(?i)(cron|scheduled|startup|init)\s+(script|job|task)\s+(web\s*shell|backdoor|reverse\s+shell|payload)",
        ],
        "severity": "critical",
        "description": "Planting persistent backdoor endpoints in web apps",
    },
}


@dataclass
class WebShellEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_path: str = ""
    command: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[WebShellEvent] = field(default_factory=list)


@dataclass
class ShellChain:
    agent: str = ""
    steps: list[WebShellEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class WebShellReport:
    total_events: int = 0
    shell_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    shell_chains: list[ShellChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(web\s*shell|reverse.shell|backdoor|c99|r57|weevely|china.chopper|"
    r"file.manager|directory.traversal|obfuscat|base64.decode|"
    r"meterpreter|metasploit|shell.exec|command.inject)\b"
)


def classify_event(event: dict) -> dict:
    text = " ".join(str(v) for v in event.values())
    best_cat = ""
    best_confidence = 0.0
    indicators: list[str] = []

    for cat in CATEGORIES:
        match_count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                match_count += 1
        if match_count > 0:
            confidence = min(1.0, match_count * 0.3)
            if confidence > best_confidence:
                best_confidence = confidence
                best_cat = cat
            indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = WebShellReport(total_events=len(events))
    cat_events: dict[str, list[WebShellEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.shell_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            wse = WebShellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_path=str(ev.get("path", ev.get("target_path", ""))),
                command=str(ev.get("command", ev.get("cmd", "")))[:200],
                raw=ev,
            )
            cat_events[cat].append(wse)
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

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * severity_weight.get(cs.severity, 0.3)

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
    report.shell_chains = detect_chains(events)

    return _report_to_dict(report)


def detect_chains(events: list[dict]) -> list[ShellChain]:
    agent_events: dict[str, list[WebShellEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            wse = WebShellEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(wse)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(ShellChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                chain_score=round(score, 2),
            ))
    return chains[:20]


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
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


def _report_to_dict(report: WebShellReport) -> dict:
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
    for chain in data.get("shell_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Web Shell Detection Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Shell events: {analysis.get('shell_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("shell_chains", [])
    if chains:
        lines.append("")
        lines.append("Shell chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
