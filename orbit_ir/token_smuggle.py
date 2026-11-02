"""Token smuggling detection for agent incident reconstruction.

Detects patterns where agents embed hidden payloads in outputs:
- invisible_unicode: zero-width characters, RTL overrides, homoglyphs
- base64_payload: base64-encoded instructions or credentials in outputs
- steganographic_encoding: data hidden in whitespace, casing, punctuation
- hidden_instruction: concealed directives in seemingly benign text
- credential_embedding: tokens/keys/secrets embedded in agent outputs
- control_sequence: terminal/ANSI escape sequences used to hide content
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "invisible_unicode": {
        "patterns": [
            r"(?i)(zero.width|zwsp|zwnj|zwj|U\+200[0-9A-Fa-f]|U\+FEFF|\\u200[0-9a-f])",
            r"(?i)(invisible|hidden)\s+(char|character|unicode|codepoint|text)",
            r"(?i)(RTL|right.to.left)\s+(override|mark|embed|control)",
            r"(?i)(homoglyph|lookalike|confusable)\s+(char|character|substitut|attack)",
            r"(?i)(bidi|bidirectional)\s+(override|attack|trick|spoof)",
        ],
        "severity": "high",
        "description": "Zero-width characters, RTL overrides, or homoglyphs used to hide content",
    },
    "base64_payload": {
        "patterns": [
            r"(?i)(base64|b64)\s+(encod|payload|hidden|embed|inject|smuggl)",
            r"(?i)(hidden|smuggl|embed)\w*\s+(base64|b64|encoded)\s+(data|payload|content|string)",
            r"(?i)(decode|extract)\w*\s+(base64|b64)\s+(payload|hidden|secret|embed)",
            r"(?i)(suspicio|unexpect|anomal)\w*\s+(base64|b64|encod)\s+(string|data|block)",
        ],
        "severity": "high",
        "description": "Base64-encoded payloads hidden in agent outputs",
    },
    "steganographic_encoding": {
        "patterns": [
            r"(?i)(stegan|stego)\w*\s+(encod|embed|hidden|payload|data|channel)",
            r"(?i)(whitespace|spacing)\s+(encod|stegan|hidden|channel|exfil)",
            r"(?i)(hidden|covert)\s+(channel|encod|data)\s+(in|via|through|using)\s+(whitespace|spacing|casing|punctuat)",
            r"(?i)(bit|data)\s+(encod|embed|hidden)\s+(in|via)\s+(capitali|casing|letter|word)",
        ],
        "severity": "critical",
        "description": "Data hidden via steganographic encoding in text",
    },
    "hidden_instruction": {
        "patterns": [
            r"(?i)(hidden|conceal|embedd|inject)\w*\s+(instruct|directive|command|prompt)",
            r"(?i)(prompt|instruct)\s+(inject|smuggl|hidden|embed|conceal)",
            r"(?i)(invisible|hidden)\s+(text|content)\s+(contain|with|carry)\w*\s+(instruct|command|directive)",
            r"(?i)(indirect|second.?order)\s+(prompt|instruct)\s+(inject|attack|smuggl)",
        ],
        "severity": "critical",
        "description": "Concealed directives embedded in seemingly benign text",
    },
    "credential_embedding": {
        "patterns": [
            r"(?i)(embed|smuggl|hidden|conceal|exfil)\w*\s+(credential|token|api.key|secret|password|key)",
            r"(?i)(credential|token|api.key|secret|password)\s+(embed|smuggl|hidden|leak|exfil)\w*\s+(in|within|inside)",
            r"(?i)(output|response|message)\s+(contain|include|embed)\w*\s+(credential|token|secret|key|password)",
            r"(?i)(sensitive|secret)\s+(data|info)\s+(embed|hidden|smuggl|exfil)",
        ],
        "severity": "critical",
        "description": "Credentials or secrets embedded in agent outputs",
    },
    "control_sequence": {
        "patterns": [
            r"(?i)(ANSI|terminal|escape)\s+(sequence|code|control)\s+(inject|hidden|smuggl|embed|abuse)",
            r"(?i)(\\x1b|\\033|\\e)\s*\[",
            r"(?i)(control|escape)\s+(char|character|sequence)\s+(hidden|inject|smuggl|abuse)",
            r"(?i)(terminal|console)\s+(manipulat|hijack|inject|spoof)\w*\s+(via|using|with)\s+(escape|ANSI|control)",
        ],
        "severity": "high",
        "description": "Terminal/ANSI escape sequences used to hide or manipulate output",
    },
}


@dataclass
class SmuggleEvent:
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
    events: list[SmuggleEvent] = field(default_factory=list)


@dataclass
class SmuggleChain:
    agent: str = ""
    steps: list[SmuggleEvent] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)


@dataclass
class TokenSmuggleReport:
    total_events: int = 0
    smuggle_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    techniques_seen: list[str] = field(default_factory=list)
    smuggle_chains: list[SmuggleChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(zero.width|zwsp|homoglyph|base64|b64|steganograph|stego|whitespace.encod|"
    r"hidden.instruct|prompt.inject|credential.embed|ansi.escape|control.sequence|"
    r"bidi|rtl.override|invisible.unicode)\b"
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


def _detect_chains(events: list[dict]) -> list[SmuggleChain]:
    from collections import defaultdict

    agent_events: dict[str, list[SmuggleEvent]] = defaultdict(list)

    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        matches = _classify_event(ev)
        for cat, technique in matches:
            se = SmuggleEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(se)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            techniques = sorted(set(se.technique for se in sevents if se.technique))
            chains.append(SmuggleChain(
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


def analyze_token_smuggling(events_or_dir: str | Path | list[dict]) -> TokenSmuggleReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> TokenSmuggleReport:
    report = TokenSmuggleReport(total_events=len(events))

    cat_events: dict[str, list[SmuggleEvent]] = {c: [] for c in CATEGORIES}
    techniques_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.smuggle_events += 1
        for cat, technique in matches:
            e = SmuggleEvent(
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
    report.smuggle_chains = _detect_chains(events)

    return report


def format_text(report: TokenSmuggleReport) -> str:
    lines = [
        "Token Smuggling Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Smuggle events: {report.smuggle_events}",
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

    if report.smuggle_chains:
        lines.append("")
        lines.append("Smuggle chains:")
        for c in report.smuggle_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, techniques: {', '.join(c.techniques_used)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: TokenSmuggleReport) -> str:
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
    for chain in data.get("smuggle_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
