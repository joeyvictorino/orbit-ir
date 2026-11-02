"""Kill chain completeness scoring and gap detection.

Maps observed MITRE ATT&CK techniques to kill chain phases,
scores coverage per phase, and identifies gaps where attacker
activity may be undetected.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .mitre_report import TECHNIQUE_CATALOG, ALL_TACTICS

KILL_CHAIN_PHASES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
]

PHASE_WEIGHTS = {
    "Initial Access": 1.0,
    "Execution": 0.9,
    "Persistence": 0.8,
    "Privilege Escalation": 0.9,
    "Defense Evasion": 0.7,
    "Credential Access": 0.8,
    "Discovery": 0.6,
    "Lateral Movement": 0.8,
    "Collection": 0.7,
    "Exfiltration": 1.0,
    "Command and Control": 0.9,
}


@dataclass
class PhaseResult:
    phase: str
    covered: bool
    techniques_observed: list[str] = field(default_factory=list)
    technique_count: int = 0
    total_techniques: int = 0
    coverage_pct: float = 0.0
    weight: float = 1.0


@dataclass
class KillChainGap:
    phase: str
    severity: str  # critical, high, medium, low
    description: str
    missing_techniques: list[str] = field(default_factory=list)


@dataclass
class KillChainReport:
    phases: list[PhaseResult]
    gaps: list[KillChainGap]
    overall_score: float
    phases_covered: int
    phases_total: int
    longest_chain: int
    chain_segments: list[list[str]]
    grade: str


def _techniques_by_tactic() -> dict[str, list[str]]:
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for tid, info in TECHNIQUE_CATALOG.items():
        by_tactic[info["tactic"]].append(tid)
    return dict(by_tactic)


def _extract_techniques(events: list[dict[str, Any]]) -> set[str]:
    techniques: set[str] = set()
    for event in events:
        for key in ("mitre_technique", "technique_id", "technique"):
            val = event.get(key, "")
            if val and isinstance(val, str) and val.startswith("T"):
                techniques.add(val)
        tags = event.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("T") and len(tag) >= 5 and tag[1:5].isdigit():
                    techniques.add(tag.split(".")[0] if "." in tag else tag)
        mitre_list = event.get("mitre_techniques", [])
        if isinstance(mitre_list, list):
            for t in mitre_list:
                if isinstance(t, str) and t.startswith("T"):
                    techniques.add(t)
    return techniques


def analyze_kill_chain(
    events: list[dict[str, Any]],
) -> KillChainReport:
    tactic_techs = _techniques_by_tactic()
    observed = _extract_techniques(events)

    phases: list[PhaseResult] = []
    for phase in KILL_CHAIN_PHASES:
        available = tactic_techs.get(phase, [])
        found = [t for t in available if t in observed]
        coverage = len(found) / len(available) * 100 if available else 0
        phases.append(PhaseResult(
            phase=phase,
            covered=len(found) > 0,
            techniques_observed=sorted(found),
            technique_count=len(found),
            total_techniques=len(available),
            coverage_pct=round(coverage, 1),
            weight=PHASE_WEIGHTS.get(phase, 1.0),
        ))

    gaps = _detect_gaps(phases, tactic_techs, observed)

    covered_count = sum(1 for p in phases if p.covered)
    longest, segments = _find_chain_segments(phases)

    weighted_sum = 0.0
    weight_total = 0.0
    for p in phases:
        w = p.weight
        weight_total += w
        if p.covered:
            weighted_sum += w * min(p.coverage_pct / 100, 1.0)

    overall = round(weighted_sum / weight_total * 100, 1) if weight_total > 0 else 0

    return KillChainReport(
        phases=phases,
        gaps=gaps,
        overall_score=overall,
        phases_covered=covered_count,
        phases_total=len(KILL_CHAIN_PHASES),
        longest_chain=longest,
        chain_segments=segments,
        grade=_grade(overall),
    )


def _detect_gaps(
    phases: list[PhaseResult],
    tactic_techs: dict[str, list[str]],
    observed: set[str],
) -> list[KillChainGap]:
    gaps: list[KillChainGap] = []
    for p in phases:
        if p.covered:
            continue
        available = tactic_techs.get(p.phase, [])
        missing = [t for t in available if t not in observed]
        sev = _gap_severity(p.phase, phases)
        desc = f"No techniques observed for {p.phase}"
        if p.phase in ("Initial Access", "Exfiltration"):
            desc += "; this is a critical kill chain phase"
        gaps.append(KillChainGap(
            phase=p.phase,
            severity=sev,
            description=desc,
            missing_techniques=sorted(missing),
        ))
    return gaps


def _gap_severity(phase: str, phases: list[PhaseResult]) -> str:
    phase_map = {p.phase: p for p in phases}
    idx = KILL_CHAIN_PHASES.index(phase) if phase in KILL_CHAIN_PHASES else -1

    has_before = idx > 0 and phase_map.get(KILL_CHAIN_PHASES[idx - 1], PhaseResult(phase="", covered=False)).covered
    has_after = idx < len(KILL_CHAIN_PHASES) - 1 and phase_map.get(KILL_CHAIN_PHASES[idx + 1], PhaseResult(phase="", covered=False)).covered

    if has_before and has_after:
        return "critical"
    if phase in ("Initial Access", "Exfiltration", "Execution"):
        return "high"
    if has_before or has_after:
        return "medium"
    return "low"


def _find_chain_segments(phases: list[PhaseResult]) -> tuple[int, list[list[str]]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for p in phases:
        if p.covered:
            current.append(p.phase)
        else:
            if current:
                segments.append(current)
                current = []
    if current:
        segments.append(current)

    longest = max((len(s) for s in segments), default=0)
    return longest, segments


def _grade(score: float) -> str:
    if score >= 80:
        return "A"
    if score >= 60:
        return "B"
    if score >= 40:
        return "C"
    if score >= 20:
        return "D"
    return "F"


def format_kill_chain_text(report: KillChainReport) -> str:
    lines = [
        "Kill Chain Completeness Analysis",
        "=" * 62,
        "",
        f"  Overall Score: {report.overall_score}% (Grade: {report.grade})",
        f"  Phases Covered: {report.phases_covered}/{report.phases_total}",
        f"  Longest Chain: {report.longest_chain} consecutive phases",
        "",
    ]

    lines.append(f"  {'Phase':<25} {'Status':<10} {'Techniques':<12} {'Coverage':<10}")
    lines.append("  " + "-" * 60)
    for p in report.phases:
        status = "COVERED" if p.covered else "GAP"
        techs = f"{p.technique_count}/{p.total_techniques}"
        cov = f"{p.coverage_pct}%"
        lines.append(f"  {p.phase:<25} {status:<10} {techs:<12} {cov:<10}")

    lines.append("")

    if report.gaps:
        lines.append("  Gaps Detected:")
        lines.append("  " + "-" * 60)
        for g in report.gaps:
            lines.append(f"  [{g.severity.upper()}] {g.phase}: {g.description}")
            if g.missing_techniques:
                techs = ", ".join(g.missing_techniques[:5])
                if len(g.missing_techniques) > 5:
                    techs += f" (+{len(g.missing_techniques) - 5} more)"
                lines.append(f"         Missing: {techs}")
        lines.append("")

    if report.chain_segments:
        lines.append("  Chain Segments:")
        for i, seg in enumerate(report.chain_segments, 1):
            lines.append(f"    {i}. {' -> '.join(seg)}")
        lines.append("")

    return "\n".join(lines)


def load_and_analyze(
    events_path: str | Path,
) -> KillChainReport:
    p = Path(events_path)
    events: list[dict[str, Any]] = []
    if p.is_file():
        data = json.loads(p.read_text())
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict):
            events = data.get("events", data.get("timeline", []))
    elif p.is_dir():
        for f in sorted(p.glob("*.json")):
            try:
                d = json.loads(f.read_text())
                if isinstance(d, list):
                    events.extend(d)
                elif isinstance(d, dict):
                    events.extend(d.get("events", d.get("timeline", [])))
            except (json.JSONDecodeError, OSError):
                continue

    return analyze_kill_chain(events)
