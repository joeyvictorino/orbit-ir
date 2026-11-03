"""Fileless attack detection for agent incident reconstruction.

Detects patterns where agents execute attacks without writing to disk:
- memory_execution: running code directly in memory without file creation
- powershell_cradle: using PowerShell download cradles for in-memory execution
- lolbin_abuse: living-off-the-land binary abuse for proxy execution
- reflective_loading: reflective DLL/assembly loading into process memory
- script_injection: injecting scripts into legitimate interpreter processes
- wmi_abuse: using WMI/COM for fileless persistence and execution
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "memory_execution": {
        "patterns": [
            r"(?i)(memory|in.?memory|mem.?only)\s+(execution|exec|run|load|inject|payload)",
            r"(?i)(execut|run|load|inject)\w*\s+(in|from|into|via)\s+(memory|ram|heap|stack)",
            r"(?i)(fileless|disk.?less|file.?free)\s+(execution|payload|attack|malware|technique)",
            r"(?i)(virtual.?alloc|heap.?alloc|mmap)\w*\s+(shellcode|payload|code|buffer)",
        ],
        "severity": "critical",
        "description": "Running code directly in memory without writing files to disk",
    },
    "powershell_cradle": {
        "patterns": [
            r"(?i)(powershell|pwsh|ps1)\s+(cradle|download|iex|invoke.?expression|web.?request)",
            r"(?i)(invoke.?expression|iex|invoke.?command)\s*[\(\{]?\s*(new.?object|download|web|net\.webclient)",
            r"(?i)(download.?string|download.?data|web.?request|net\.webclient)\s+(invoke|iex|execute|run|pipe)",
            r"(?i)(encoded.?command|bypass|hidden.?window|no.?profile)\s+(powershell|pwsh|ps1|script)",
        ],
        "severity": "critical",
        "description": "Using PowerShell download cradles for in-memory code execution",
    },
    "lolbin_abuse": {
        "patterns": [
            r"(?i)(lolbin|lolbas|living.off.the.land|lotl|dual.?use)\s+(abuse|binary|technique|attack)",
            r"(?i)(mshta|certutil|bitsadmin|msiexec|regsvr32|rundll32|cmstp|installutil|regasm|regsvcs)\s+(download|exec|proxy|load|run|abuse|bypass)",
            r"(?i)(proxy|abuse|misuse|hijack)\w*\s+(mshta|certutil|bitsadmin|msiexec|regsvr32|rundll32|wmic|cmstp)",
            r"(?i)(signed.?binary|trusted.?binary|legitimate.?tool)\s+(proxy|abuse|hijack|misuse)\w*\s+(execution|load|download)",
        ],
        "severity": "high",
        "description": "Abusing legitimate system binaries (LOLBins) for proxy execution",
    },
    "reflective_loading": {
        "patterns": [
            r"(?i)(reflective|reflect)\w*\s+(load|inject|dll|assembly|module|pe)",
            r"(?i)(dll|assembly|module|pe)\s+(reflective|reflect)\w*\s+(load|inject|map)",
            r"(?i)(in.?memory|memory.?only)\s+(dll|assembly|module|pe)\s+(load|inject|map|execution)",
            r"(?i)(manual.?map|process.?hollow|pe.?inject)\w*\s+(dll|assembly|payload|module)",
        ],
        "severity": "critical",
        "description": "Loading DLLs or assemblies reflectively into process memory",
    },
    "script_injection": {
        "patterns": [
            r"(?i)(script|code)\s+(inject|injection|embed|insert)\w*\s+(into|via|through)\s+(process|interpreter|runtime|host)",
            r"(?i)(inject|embed|insert)\w*\s+(script|code|payload|macro)\s+(into|via|through)\s+(process|interpreter|wscript|cscript|mshta)",
            r"(?i)(vbscript|jscript|javascript|macro)\s+(inject|injection|embed|execute)\w*\s+(process|memory|runtime)",
            r"(?i)(process|interpreter|host)\s+(script|code)\s+(injection|inject|embed|execution)",
        ],
        "severity": "high",
        "description": "Injecting malicious scripts into legitimate interpreter processes",
    },
    "wmi_abuse": {
        "patterns": [
            r"(?i)(wmi|wmic|com.?object|dcom)\s+(abuse|persist|exec|execut|lateral|remote|event|subscription)",
            r"(?i)(wmi|wmic)\s+(event|subscription|filter|consumer|binding)\s+(persist|create|install|register)",
            r"(?i)(fileless|memory)\s+(persist|technique|attack)\s+(via|through|using)\s+(wmi|com|dcom|wmic)",
            r"(?i)(event.?subscription|event.?filter|event.?consumer)\s+(wmi|wmiprvse|scrcons|activescript)",
        ],
        "severity": "high",
        "description": "Using WMI/COM objects for fileless persistence and execution",
    },
}


@dataclass
class FilelessEvent:
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
    events: list[FilelessEvent] = field(default_factory=list)


@dataclass
class FilelessChain:
    agent: str = ""
    steps: list[FilelessEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class FilelessAttackReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[FilelessChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(memory.execution|powershell.cradle|lolbin|living.off.the.land|"
    r"reflective.load|manual.map|process.hollow|script.inject|"
    r"wmi.abuse|event.subscription|fileless|in.memory|"
    r"certutil|mshta|bitsadmin|regsvr32|rundll32)\b"
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


def _detect_chains(events: list[dict]) -> list[FilelessChain]:
    agent_events: dict[str, list[FilelessEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            fe = FilelessEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(fe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(FilelessChain(
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


def analyze_fileless_attacks(events_or_dir: str | Path | list[dict]) -> FilelessAttackReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> FilelessAttackReport:
    report = FilelessAttackReport(total_events=len(events))
    cat_events: dict[str, list[FilelessEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = FilelessEvent(
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


def format_text(report: FilelessAttackReport) -> str:
    lines = [
        "Fileless Attack Analysis",
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


def format_json(report: FilelessAttackReport) -> str:
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
