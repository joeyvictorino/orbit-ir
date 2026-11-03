"""USB attack detection for agent incident reconstruction.

Detects patterns where agents exhibit USB-based attack behavior:
- usb_device_spoofing: HID device emulation, BadUSB, USB Rubber Ducky patterns
- autorun_exploitation: Autorun.inf abuse, USB autoplay exploitation
- firmware_tampering: USB firmware modification, controller reprogramming
- data_exfiltration_usb: mass data copy to removable media, USB dead drops
- usb_boot_attack: boot sector modification via USB, live USB persistence
- charging_attack: juice jacking, malicious charging station patterns
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "usb_device_spoofing": {
        "patterns": [
            r"(?i)(hid|keyboard|mouse)\s+(emulat|spoof|impersonat|fake|simulat)\w*",
            r"(?i)(badusb|rubber.?ducky|usb.?armory|bash.?bunny)\w*",
            r"(?i)(usb)\s+(device|gadget)\s+(spoof|emulat|fake|clone|impersonat)\w*",
            r"(?i)(hid)\s+(attack|payload|inject|keystroke)\w*",
        ],
        "severity": "critical",
        "description": "HID device emulation, BadUSB, USB Rubber Ducky patterns",
    },
    "autorun_exploitation": {
        "patterns": [
            r"(?i)(autorun\.inf|autoplay)\s+(creat|modif|writ|drop|abus|exploit)\w*",
            r"(?i)(creat|writ|drop|deploy)\w*\s+(autorun|autoplay)\s+(file|script|payload)\w*",
            r"(?i)(usb|removable)\s+(autorun|autoplay|auto.execut)\w*\s+(exploit|abus|trigger)\w*",
            r"(?i)(autorun|autoplay)\s+(exploit|abus|bypass|trick)\w*",
        ],
        "severity": "high",
        "description": "Autorun.inf abuse, USB autoplay exploitation",
    },
    "firmware_tampering": {
        "patterns": [
            r"(?i)(usb)\s+(firmware|controller)\s+(modif|tamper|flash|reprogram|patch|overwrite)\w*",
            r"(?i)(firmware)\s+(tamper|modif|flash|reprogram|overwrite|corrupt)\w*\s+(usb|device|controller)\w*",
            r"(?i)(reprogram|reflash|flash)\w*\s+(usb|device)\s+(firmware|controller|chip)\w*",
            r"(?i)(usb)\s+(controller|chip|microcontroller)\s+(reprogram|exploit|hijack)\w*",
        ],
        "severity": "critical",
        "description": "USB firmware modification, controller reprogramming",
    },
    "data_exfiltration_usb": {
        "patterns": [
            r"(?i)(mass|bulk|large)\s+(data|file)\s+(copy|transfer|exfil|dump)\w*\s+(usb|removable|thumb|flash)\w*",
            r"(?i)(exfiltrat|steal|copy|dump|siphon)\w*\s+(data|file|document)\w*\s+(to|onto|via)\s+(usb|removable|thumb|flash)\w*",
            r"(?i)(usb)\s+(dead.?drop|data.?drop|exfil|smuggl)\w*",
            r"(?i)(removable|usb|thumb|flash)\s+(drive|media|storage)\s+(exfil|copy|dump|steal)\w*",
        ],
        "severity": "high",
        "description": "Mass data copy to removable media, USB dead drops",
    },
    "usb_boot_attack": {
        "patterns": [
            r"(?i)(boot\s+sector|mbr|uefi)\s+(modif|overwrite|infect|tamper)\w*\s+(usb|removable)\w*",
            r"(?i)(usb)\s+(boot|bootable|live)\s+(attack|persist|implant|backdoor)\w*",
            r"(?i)(live\s+usb|bootable\s+usb)\s+(persist|implant|backdoor|rootkit)\w*",
            r"(?i)(usb|removable)\s+(boot|bios|uefi)\s+(exploit|attack|modif|tamper)\w*",
        ],
        "severity": "critical",
        "description": "Boot sector modification via USB, live USB persistence",
    },
    "charging_attack": {
        "patterns": [
            r"(?i)(juice.?jack|juice.?jacking)\w*",
            r"(?i)(malicious|rogue|fake)\s+(charg|power)\w*\s+(station|port|cable|adapter)\w*",
            r"(?i)(charg|power)\w*\s+(station|port|cable|adapter)\s+(attack|exploit|compromise|tamper)\w*",
            r"(?i)(usb)\s+(charg|power)\w*\s+(data|payload|inject|intercept|sniff)\w*",
        ],
        "severity": "medium",
        "description": "Juice jacking, malicious charging station patterns",
    },
}


@dataclass
class UsbAttackEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    device_id: str = ""
    target_path: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[UsbAttackEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[UsbAttackEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class UsbAttackReport:
    total_events: int = 0
    usb_attack_events: int = 0
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
    r"(?i)\b(badusb|rubber.ducky|hid.attack|hid.emulat|"
    r"autorun|autoplay|firmware.tamper|firmware.flash|"
    r"usb.exfil|data.exfil|dead.drop|"
    r"boot.sector|live.usb|juice.jack|charging.attack)\b"
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
    report = UsbAttackReport(total_events=len(events))
    cat_events: dict[str, list[UsbAttackEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.usb_attack_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = UsbAttackEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                device_id=str(ev.get("device_id", ev.get("device", ""))),
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
    agent_events: dict[str, list[UsbAttackEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            re_ev = UsbAttackEvent(
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


def _report_to_dict(report: UsbAttackReport) -> dict:
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
        "USB Attack Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"USB attack events: {analysis.get('usb_attack_events', 0)}",
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
