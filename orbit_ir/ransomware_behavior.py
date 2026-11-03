"""Ransomware behavior detection for agent incident reconstruction.

Detects patterns where agents exhibit ransomware-like behavior:
- file_encryption_burst: rapid mass file encryption activity
- ransom_note_drop: ransom note file creation patterns
- shadow_copy_delete: volume shadow copy deletion attempts
- extension_rename: mass file extension renaming to encrypted variants
- key_exfiltration: encryption key exfiltration to external C2
- backup_destruction: systematic backup file/system destruction
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "file_encryption_burst": {
        "patterns": [
            r"(?i)(mass|bulk|rapid|burst)\s+(file\s+)?(encrypt|cipher|lock)\w*",
            r"(?i)(encrypt|cipher|lock)\w*\s+(all|every|multiple|batch|mass)\s+(file|document|data)\w*",
            r"(?i)(file|document|data)\s+(encryption|ciphering|locking)\s+(burst|spike|surge|wave)\w*",
            r"(?i)(aes|rsa|chacha|salsa)\d*\s+(encrypt|cipher)\w*\s+(file|document|disk|volume)\w*",
        ],
        "severity": "critical",
        "description": "Rapid mass file encryption activity",
    },
    "ransom_note_drop": {
        "patterns": [
            r"(?i)(ransom|readme|decrypt|recover|restore)\s*(note|instruction|message|txt|html|hta)\w*\s+(creat|drop|writ|plac|deploy)\w*",
            r"(?i)(creat|drop|writ|plac|deploy)\w*\s+(ransom|readme|decrypt)\s*(note|instruction|message|file)\w*",
            r"(?i)(how.to.decrypt|how.to.recover|your.files.are.encrypted|pay.to.decrypt)\w*",
            r"(?i)(readme\.txt|decrypt\.txt|recover\.html|ransom\.hta|help_decrypt)\w*\s+(creat|writ|drop|found)\w*",
        ],
        "severity": "critical",
        "description": "Ransom note file creation patterns",
    },
    "shadow_copy_delete": {
        "patterns": [
            r"(?i)(vssadmin|wmic)\s+(delete|remove|destroy)\s+(shadow|shadowcop)\w*",
            r"(?i)(shadow\s+cop|volume\s+shadow)\w*\s+(delet|remov|destroy|wipe|purg)\w*",
            r"(?i)(delet|remov|destroy|wipe|purg)\w*\s+(shadow\s+cop|volume\s+shadow|vss\s+snapshot)\w*",
            r"(?i)(bcdedit|wbadmin)\s+(set|delete)\s+(recoveryenabled|catalog)\w*",
        ],
        "severity": "critical",
        "description": "Volume shadow copy deletion attempts",
    },
    "extension_rename": {
        "patterns": [
            r"(?i)(renam|chang|modif|append)\w*\s+(file\s+)?(extension|suffix)\s+(to\s+)?(\.encrypted|\.locked|\.crypt|\.enc|\.ransom)\w*",
            r"(?i)(mass|bulk|batch)\s+(file\s+)?(renam|extension\s+chang)\w*",
            r"(?i)(file|document)\w*\s+(extension|suffix)\s+(renam|chang|modif|replac)\w*\s+(encrypt|lock|crypt|ransom)\w*",
            r"(?i)\.(locked|encrypted|crypt|enc|ransom|pay|decrypt)\s+(extension|suffix|appended|renamed)\w*",
        ],
        "severity": "high",
        "description": "Mass file extension renaming to encrypted variants",
    },
    "key_exfiltration": {
        "patterns": [
            r"(?i)(encryption|decryption|private|master)\s+(key|secret)\s+(exfiltrat|send|transmit|upload|post)\w*",
            r"(?i)(exfiltrat|send|transmit|upload|post)\w*\s+(encryption|decryption|private|master)\s+(key|secret)\w*",
            r"(?i)(key|secret)\s+(exchange|negotiat|handshake)\s+(with|to)\s+(c2|command|control|server|remote)\w*",
            r"(?i)(rsa|aes)\s+(key|pair)\s+(generat|creat)\w*.*\s+(send|upload|exfil|transmit)\w*",
        ],
        "severity": "critical",
        "description": "Encryption key exfiltration to external C2",
    },
    "backup_destruction": {
        "patterns": [
            r"(?i)(backup|archive|snapshot|restore\s+point)\s+(delet|remov|destroy|wipe|corrupt|overwrite)\w*",
            r"(?i)(delet|remov|destroy|wipe|corrupt|overwrite)\w*\s+(backup|archive|snapshot|restore\s+point)\w*",
            r"(?i)(disable|stop|kill)\w*\s+(backup|recovery|restore)\s+(service|process|daemon|agent)\w*",
            r"(?i)(wbadmin|vssadmin|bcdedit)\s+(delete|set)\s+(catalog|backup|recoveryenabled)\w*",
        ],
        "severity": "high",
        "description": "Systematic backup file/system destruction",
    },
}


@dataclass
class RansomwareEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    file_count: int = 0
    target_path: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[RansomwareEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[RansomwareEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class RansomwareReport:
    total_events: int = 0
    ransomware_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(file.encrypt|ransom.note|shadow.copy.delet|vssadmin|"
    r"extension.renam|key.exfil|backup.delet|backup.destroy|"
    r"mass.encrypt|bcdedit|wbadmin|ransomware)\b"
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
    report = RansomwareReport(total_events=len(events))
    cat_events: dict[str, list[RansomwareEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.ransomware_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = RansomwareEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                file_count=int(ev.get("file_count", 0)),
                target_path=str(ev.get("target_path", ev.get("path", ""))),
                raw=ev,
            )
            cat_events[cat].append(re_ev)
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
    report.attack_chains = _detect_chains(events)

    return _report_to_dict(report)


def _detect_chains(events: list[dict]) -> list[AttackChain]:
    agent_events: dict[str, list[RansomwareEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = RansomwareEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(re_ev)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AttackChain(
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


def _report_to_dict(report: RansomwareReport) -> dict:
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
    for chain in data.get("attack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Ransomware Behavior Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Ransomware events: {analysis.get('ransomware_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("attack_chains", [])
    if chains:
        lines.append("")
        lines.append("Attack chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
