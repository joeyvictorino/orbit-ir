"""Keylogger and input capture pattern detection for agent incident reconstruction.

Detects patterns where agents intercept or log user input:
- keystroke_logging: capturing individual keystrokes or key events
- input_interception: intercepting input streams or stdin redirection
- clipboard_monitoring: monitoring or exfiltrating clipboard contents
- screen_capture: taking screenshots or recording screen activity
- credential_harvesting: capturing passwords or authentication tokens from input
- input_replay: recording and replaying input sequences
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "keystroke_logging": {
        "patterns": [
            r"(?i)(keystroke|keylog|key.?log|key.?press|key.?stroke)\w*\s+(log|capture|record|monitor|intercept|track)",
            r"(?i)(log|capture|record|monitor|intercept|track)\w*\s+(keystroke|keylog|key.?press|key.?event|keyboard)",
            r"(?i)(keyboard|typing)\s+(hook|intercept|monitor|capture|sniff|record)",
            r"(?i)(input.?hook|key.?hook|keyboard.?hook|SetWindowsHookEx|GetAsyncKeyState)",
        ],
        "severity": "critical",
        "description": "Capturing individual keystrokes or key events",
    },
    "input_interception": {
        "patterns": [
            r"(?i)(intercept|redirect|hijack|tap|divert)\w*\s+(input|stdin|user.?input|console|terminal)",
            r"(?i)(input|stdin|user.?input|console)\s+(intercept|redirect|hijack|tap|divert|capture)",
            r"(?i)(man.in.the.middle|mitm|proxy)\w*\s+(input|keyboard|terminal|console)",
            r"(?i)(pty|pseudo.?terminal|tty)\s+(intercept|monitor|sniff|capture|clone|spy)",
        ],
        "severity": "critical",
        "description": "Intercepting input streams or stdin redirection",
    },
    "clipboard_monitoring": {
        "patterns": [
            r"(?i)(clipboard|paste.?board|copy.?buffer)\s+(monitor|capture|read|exfiltrat|sniff|access|steal|watch)",
            r"(?i)(monitor|capture|read|exfiltrat|sniff|steal|watch)\w*\s+(clipboard|paste.?board|copy.?buffer)",
            r"(?i)(clipboard|paste.?board)\s+(data|content|history|log)",
            r"(?i)(GetClipboardData|ClipboardManager|pbpaste|xclip|xsel)\s+(call|invoke|access|read)",
        ],
        "severity": "high",
        "description": "Monitoring or exfiltrating clipboard contents",
    },
    "screen_capture": {
        "patterns": [
            r"(?i)(screen|display|desktop|window)\s+(capture|record|screenshot|grab|sniff|dump)",
            r"(?i)(screenshot|screen.?grab|screen.?shot|screen.?record)\w*\s+(taken|captured|saved|upload|exfiltrat)",
            r"(?i)(capture|record|grab|dump)\w*\s+(screen|display|desktop|window|frame.?buffer)",
            r"(?i)(BitBlt|CopyFromScreen|screencapture|scrot|import.?display)\s+(call|invoke|use|execut)",
        ],
        "severity": "high",
        "description": "Taking screenshots or recording screen activity",
    },
    "credential_harvesting": {
        "patterns": [
            r"(?i)(credential|password|passphrase|auth.?token|secret)\s+(harvest|capture|intercept|steal|log|record|sniff|extract)",
            r"(?i)(harvest|capture|intercept|steal|log|record|sniff|extract)\w*\s+(credential|password|passphrase|auth.?token|login)",
            r"(?i)(fake|phony|spoofed|decoy)\s+(login|auth|prompt|dialog|form)\s+(to\s+)?(capture|harvest|steal|collect)",
            r"(?i)(credential|password)\s+(dump|spray|stuff|brute|crack|phish)",
        ],
        "severity": "critical",
        "description": "Capturing passwords or authentication tokens from input",
    },
    "input_replay": {
        "patterns": [
            r"(?i)(input|keystroke|key.?event|command)\s+(replay|playback|repeat|reproduce|re.?inject|re.?submit)",
            r"(?i)(replay|playback|repeat|reproduce)\w*\s+(input|keystroke|key.?event|command|session|interaction)",
            r"(?i)(record|capture)\w*\s+(and\s+)?(replay|playback|repeat|reproduce)\w*\s+(input|keystroke|session)",
            r"(?i)(macro|script|automation)\s+(replay|inject|simulate|mimic)\w*\s+(input|keystroke|action|command)",
        ],
        "severity": "high",
        "description": "Recording and replaying input sequences",
    },
}


@dataclass
class KeyloggerEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    capture_method: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[KeyloggerEvent] = field(default_factory=list)


@dataclass
class KeyloggerChain:
    agent: str = ""
    steps: list[KeyloggerEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class KeyloggerReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[KeyloggerChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(keystroke.log|keylog|input.intercept|clipboard.monitor|"
    r"screen.capture|credential.harvest|input.replay|"
    r"keyboard.hook|stdin.redirect|clipboard.exfiltrat)\b"
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


def _detect_chains(events: list[dict]) -> list[KeyloggerChain]:
    agent_events: dict[str, list[KeyloggerEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = KeyloggerEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                capture_method=str(ev.get("capture_method", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(KeyloggerChain(
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


def analyze_keylogger(events_or_dir: str | Path | list[dict]) -> KeyloggerReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> KeyloggerReport:
    report = KeyloggerReport(total_events=len(events))
    cat_events: dict[str, list[KeyloggerEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = KeyloggerEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                capture_method=str(ev.get("capture_method", "")),
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


def format_text(report: KeyloggerReport) -> str:
    lines = [
        "Keylogger Detection Analysis",
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


def format_json(report: KeyloggerReport) -> str:
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
