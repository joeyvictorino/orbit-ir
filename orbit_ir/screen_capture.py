"""Screen capture attack pattern detection for agent incident reconstruction.

Detects patterns where agents capture, record, or exfiltrate screen content:
- screenshot_exfil: Taking and exfiltrating screenshots of user activity
- screen_recording: Continuous or periodic screen recording without consent
- clipboard_theft: Intercepting and exfiltrating clipboard contents
- keylogging: Recording keystrokes to capture sensitive input
- display_overlay: Overlaying fake UI elements to deceive users
- ocr_extraction: Using OCR to extract text from captured screen images
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "screenshot_exfil": {
        "patterns": [
            r"(?i)(screenshot|screen.capture|screen.grab|screen.shot)\s+(exfil|upload|send|transmit|steal|extract|leak)",
            r"(?i)(exfil|upload|send|transmit|steal|extract|leak)\w*\s+(screenshot|screen.capture|screen.grab|screen.image)",
            r"(?i)(capture|grab|take)\w*\s+(screen|desktop|display|window)\w*\s+(image|shot|picture|snap)",
            r"(?i)(periodic|scheduled|timed|recurring)\s+(screenshot|screen.capture|screen.grab)",
        ],
        "severity": "high",
        "description": "Taking and exfiltrating screenshots of user activity",
    },
    "screen_recording": {
        "patterns": [
            r"(?i)(screen|desktop|display)\s+(record|capture|stream|mirror|broadcast|surveil)",
            r"(?i)(record|capture|stream|mirror|broadcast|surveil)\w*\s+(screen|desktop|display|monitor|window)",
            r"(?i)(video|media)\s+(capture|record|stream)\w*\s+(screen|desktop|display|window)",
            r"(?i)(continuous|covert|hidden|stealth|background)\s+(screen|display|desktop)\s+(record|capture|monitor)",
        ],
        "severity": "high",
        "description": "Continuous or periodic screen recording without user consent",
    },
    "clipboard_theft": {
        "patterns": [
            r"(?i)(clipboard|pasteboard|clip.board)\s+(steal|exfil|capture|intercept|monitor|sniff|read|extract|log)",
            r"(?i)(steal|exfil|capture|intercept|monitor|sniff|extract|log)\w*\s+(clipboard|pasteboard|clip.board)",
            r"(?i)(clipboard|pasteboard)\s+(content|data|text|history)\s+(steal|exfil|capture|extract|send|leak)",
            r"(?i)(monitor|watch|track|intercept)\w*\s+(copy|paste|cut)\s+(event|action|operation|activity)",
        ],
        "severity": "high",
        "description": "Intercepting and exfiltrating clipboard contents",
    },
    "keylogging": {
        "patterns": [
            r"(?i)(keylog|key.log|keystroke.log|keyboard.log|key.capture|keystroke.capture)",
            r"(?i)(log|record|capture|intercept|monitor|sniff)\w*\s+(keystroke|keypress|key.event|keyboard.input|typing)",
            r"(?i)(keystroke|keypress|key.event|keyboard.input|typing)\s+(log|record|capture|intercept|monitor|sniff|track)",
            r"(?i)(input|keyboard)\s+(hook|intercept|capture|monitor|spy|surveil|sniff)",
        ],
        "severity": "critical",
        "description": "Recording keystrokes to capture sensitive user input",
    },
    "display_overlay": {
        "patterns": [
            r"(?i)(display|screen|ui|window)\s+(overlay|spoof|fake|inject|manipulat|tamper)",
            r"(?i)(overlay|spoof|fake|inject)\w*\s+(display|screen|ui|window|dialog|prompt|form)",
            r"(?i)(fake|fraudulent|phishing|deceptive|malicious)\s+(dialog|prompt|window|overlay|popup|notification|login)",
            r"(?i)(clickjack|click.jack|ui.redress|tapjack|tap.jack)",
        ],
        "severity": "high",
        "description": "Overlaying fake UI elements to deceive users into entering data",
    },
    "ocr_extraction": {
        "patterns": [
            r"(?i)(ocr|optical.character)\s+(extract|scan|read|capture|process)\w*\s*(screen|image|screenshot|display|text)?",
            r"(?i)(extract|scan|read|capture)\w*\s+(text|content|data)\s+(from|via|using)\s+(screen|image|screenshot|display|ocr)",
            r"(?i)(screen|screenshot|display|image)\s+(text|content)\s+(extract|scan|read|parse|ocr)",
            r"(?i)(tesseract|easyocr|paddleocr|ocr.engine|text.recognition)\s+(scan|extract|process|run|execute)",
        ],
        "severity": "medium",
        "description": "Using OCR to extract text from captured screen images",
    },
}


@dataclass
class CaptureEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target: str = ""
    method: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[CaptureEvent] = field(default_factory=list)


@dataclass
class CaptureChain:
    agent: str = ""
    steps: list[CaptureEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    capture_score: float = 0.0


@dataclass
class CaptureReport:
    total_events: int = 0
    capture_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    capture_chains: list[CaptureChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(screenshot.exfil|screen.record|clipboard.theft|"
    r"keylog|display.overlay|ocr.extract|key.capture|"
    r"screen.capture|clipboard.monitor|clickjack|tapjack)\b"
)


def classify_event(event: dict) -> dict:
    """Classify a single event for screen capture attack patterns."""
    text = " ".join(str(v) for v in event.values())
    result: dict[str, Any] = {"category": "none", "confidence": 0.0, "indicators": []}
    best_count = 0

    for cat in CATEGORIES:
        count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                count += 1
        if count > best_count:
            best_count = count
            result["category"] = cat
            result["indicators"] = [CATEGORIES[cat]["description"]]

    if best_count > 0:
        result["confidence"] = min(1.0, round(best_count * 0.35, 2))
    return result


def _classify_all(event: dict) -> list[tuple[str, str]]:
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


def detect_chains(events: list[dict]) -> list[dict]:
    """Find multi-step screen capture attack chains across events."""
    agent_events: dict[str, list[CaptureEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_all(ev)
        for cat, technique in matches:
            ce = CaptureEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                method=str(ev.get("method", "")),
                raw=ev,
            )
            agent_events[agent].append(ce)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.2)
            chains.append({
                "agent": agent,
                "steps": len(sevents),
                "categories": cats,
                "score": round(score, 2),
            })
    return chains[:20]


def load_events(path: str) -> list[dict]:
    """Load events from a JSON file or directory of JSON files."""
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file():
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


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def analyze(events: list[dict]) -> dict:
    """Analyze events for screen capture attack patterns and return summary."""
    report = CaptureReport(total_events=len(events))
    cat_events: dict[str, list[CaptureEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_all(ev)
        if matches:
            report.capture_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            ce = CaptureEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target=str(ev.get("target", "")),
                method=str(ev.get("method", "")),
                raw=ev,
            )
            cat_events[cat].append(ce)
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

    return {
        "total_events": report.total_events,
        "capture_events": report.capture_events,
        "categories": {cs.category: {"count": cs.count, "severity": cs.severity} for cs in report.categories},
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "agents_involved": report.agents_involved,
    }


def format_report(analysis: dict) -> str:
    """Format analysis results as a human-readable report."""
    lines = [
        "Screen Capture Attack Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Capture events: {analysis.get('capture_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    categories = analysis.get("categories", {})
    for cat, info in sorted(categories.items()):
        if info.get("count", 0) > 0:
            lines.append(f"  {cat:<30s}  {info['count']:>3d} events  severity={info.get('severity', 'medium')}")

    if analysis.get("agents_involved"):
        lines.append("")
        lines.append("Agents: " + ", ".join(analysis["agents_involved"]))

    lines.append("")
    return "\n".join(lines)
