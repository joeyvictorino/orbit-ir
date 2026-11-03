"""Firmware tampering detection for agent incident reconstruction.

Detects patterns where agents attempt to modify or corrupt firmware,
bootloaders, or low-level system components:
- firmware_modify: direct modification of firmware images or UEFI/BIOS
- bootloader_tamper: tampering with bootloader configuration or binaries
- secure_boot_bypass: attempting to disable or circumvent secure boot
- firmware_implant: planting persistent implants in firmware storage
- tpm_attack: attacking Trusted Platform Module for key extraction or bypass
- supply_chain_firmware: injecting malicious code during firmware supply chain
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "firmware_modify": {
        "patterns": [
            r"(?i)(modif|alter|patch|overwrit|flash|replac)\w*\s+(firmware|bios|uefi|eeprom|nvram|spi.?flash)\s*(image|binary|code|data|region)?\s*(to|for|with|using)?\s*(inject|implant|backdoor|persist|malicious)?",
            r"(?i)(firmware|bios|uefi|eeprom|nvram)\s+(modif|alter|patch|overwrit|flash|replac|corrupt|tamper)\w*\s*(with|using|via|through)?\s*(malicious|custom|crafted|unauthorized)?",
            r"(?i)(write|flash|program|dump)\w*\s+(to|from)\s+(firmware|bios|uefi|spi.?flash|eeprom|nvram)\s*(chip|device|region|image)?",
            r"(?i)(extract|dump|read|exfiltrat)\w*\s+(firmware|bios|uefi|spi.?flash|eeprom)\s+(image|binary|content|data)\s+(for|to)\s+(analys|reverse|modif|tamper)",
        ],
        "severity": "critical",
        "description": "Direct modification of firmware images or UEFI/BIOS components",
    },
    "bootloader_tamper": {
        "patterns": [
            r"(?i)(tamper|modif|alter|replac|patch|infect)\w*\s+(bootloader|grub|boot.?manager|mbr|vbr|boot.?sector|boot.?record)\s*(to|for|with)?\s*(persist|backdoor|inject|bypass|disable)?",
            r"(?i)(bootloader|grub|boot.?manager|mbr|vbr)\s+(tamper|modif|infect|corrupt|replac|inject)\w*\s*(with|using|via)?\s*(malicious|custom|unauthorized|rootkit)?",
            r"(?i)(inject|plant|embed|hid)\w*\s+(malicious\s+)?(code|payload|backdoor|rootkit)\s+(in|into|within)\s+(bootloader|grub|mbr|boot.?sector|boot.?record)",
            r"(?i)(bootkits?|boot.?level\s+rootkit|evil.?maid)\s+(attack|implant|infect|deploy|install)\w*\s*(on|to|into|against)?\s*(target|victim|system|device)?",
        ],
        "severity": "critical",
        "description": "Tampering with bootloader configuration or binaries",
    },
    "secure_boot_bypass": {
        "patterns": [
            r"(?i)(bypass|disabl|circumvent|defeat|subvert)\w*\s+(secure\s+boot|verified\s+boot|trusted\s+boot|measured\s+boot)\s*(mechanism|check|validation|verification|policy)?",
            r"(?i)(secure\s+boot)\s+(bypass|disabl|circumvent|defeat|subvert|violat)\w*\s*(using|via|through|with)?\s*(exploit|vulnerability|shim|signed|key)?",
            r"(?i)(sign|enroll|inject)\w*\s+(unauthorized|malicious|custom|forged)\s+(key|certificate|binary|driver)\s+(to|for|into)\s+(secure\s+boot|uefi|firmware)\s*(database|db|dbx|mok)?",
            r"(?i)(exploit|abus|leverag)\w*\s+(secure\s+boot\s+)?(vulnerability|weakness|flaw|bug)\s+(to|for)\s+(bypass|disabl|circumvent|load)\w*\s+(unsigned|unverified|malicious|unauthorized)",
        ],
        "severity": "critical",
        "description": "Attempting to disable or circumvent secure boot mechanisms",
    },
    "firmware_implant": {
        "patterns": [
            r"(?i)(plant|embed|inject|install|deploy)\w*\s+(persistent\s+)?(implant|backdoor|rootkit|payload|malware)\s+(in|into|within|inside)\s+(firmware|bios|uefi|spi.?flash|eeprom|nvram)",
            r"(?i)(firmware|bios|uefi)\s+(implant|backdoor|rootkit|persistent)\s+(plant|embed|inject|install|deploy|establish)\w*\s*(for|to|using)?\s*(persist|surviv|stealth|long.?term)?",
            r"(?i)(persist|surviv)\w*\s+(across|through|beyond)\s+(os\s+reinstall|format|reboot|disk.?wipe|factory.?reset)\s+(using|via|with|through)\s+(firmware|bios|uefi|spi)\s*(implant|backdoor|rootkit)?",
            r"(?i)(spi.?flash|eeprom|nvram|smm|system.?management)\s+(implant|backdoor|rootkit|payload)\s+(that\s+)?(persist|surviv|resist|evad)\w*\s*(detection|removal|reinstall|wipe)?",
        ],
        "severity": "critical",
        "description": "Planting persistent implants in firmware storage",
    },
    "tpm_attack": {
        "patterns": [
            r"(?i)(attack|exploit|bypass|extract|compromise)\w*\s+(tpm|trusted\s+platform\s+module|tpm\s*2?\.\s*0?)\s*(key|secret|seal|pcr|attestation|measurement)?\s*(to|for)?\s*(extract|bypass|forge|unseal)?",
            r"(?i)(tpm|trusted\s+platform)\s+(attack|exploit|bypass|sniff|intercept|reset|clear)\w*\s*(to|for|using|via)?\s*(extract|forge|bypass|unseal|intercept)?\s*(key|secret|credential|measurement)?",
            r"(?i)(sniff|intercept|tap|prob)\w*\s+(tpm|spi)\s+(bus|communication|interface|signal)\s+(to|for)\s+(extract|captur|intercept|recover)\s+(key|secret|measurement|pcr)",
            r"(?i)(reset|clear|forge|spoof)\w*\s+(tpm|pcr)\s+(value|measurement|state|register)\s+(to|for)\s+(bypass|circumvent|defeat|trick)\s+(attestation|seal|verification|integrity)",
        ],
        "severity": "high",
        "description": "Attacking Trusted Platform Module for key extraction or bypass",
    },
    "supply_chain_firmware": {
        "patterns": [
            r"(?i)(inject|implant|embed|insert)\w*\s+(malicious\s+)?(code|backdoor|implant|payload)\s+(during|in|into)\s+(firmware\s+)?(supply.?chain|manufacturing|production|distribution|update)\s*(process|pipeline|stage)?",
            r"(?i)(supply.?chain)\s+(firmware\s+)?(attack|compromise|tamper|inject|implant)\w*\s*(during|at|in)?\s*(manufacturing|production|distribution|update|delivery)?",
            r"(?i)(compromis|tamper|infect|trojaniz)\w*\s+(firmware\s+)?(update|package|image|binary|distribution)\s+(before|during|in)\s+(delivery|download|install|deploy|distribut)",
            r"(?i)(intercept|redirect|tamper)\w*\s+(firmware\s+)?(update|download|ota|distribution)\s+(channel|server|mechanism|process)\s+(to|for)\s+(inject|deliver|install)\w*\s+(malicious|trojanized|backdoored)",
        ],
        "severity": "critical",
        "description": "Injecting malicious code during firmware supply chain process",
    },
}


@dataclass
class FirmwareTamperEvent:
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
    events: list[FirmwareTamperEvent] = field(default_factory=list)


@dataclass
class FirmwareTamperChain:
    agent: str = ""
    steps: list[FirmwareTamperEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class FirmwareTamperReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[FirmwareTamperChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(bootkit|evil.?maid|spi.?flash|uefi.?rootkit|"
    r"tpm.?sniff|firmware.?implant|secure.?boot.?bypass|"
    r"bios.?tamper|nvram.?attack|smm.?exploit|pcr.?reset)\b"
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


def _detect_chains(events: list[dict]) -> list[FirmwareTamperChain]:
    agent_events: dict[str, list[FirmwareTamperEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = FirmwareTamperEvent(
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
            chains.append(FirmwareTamperChain(
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


def analyze_firmware_tamper(events_or_dir: str | Path | list[dict]) -> FirmwareTamperReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> FirmwareTamperReport:
    report = FirmwareTamperReport(total_events=len(events))
    cat_events: dict[str, list[FirmwareTamperEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = FirmwareTamperEvent(
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


def format_text(report: FirmwareTamperReport) -> str:
    lines = [
        "Firmware Tampering Analysis",
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


def format_json(report: FirmwareTamperReport) -> str:
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
