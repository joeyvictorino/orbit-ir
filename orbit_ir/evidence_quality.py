"""Evidence quality scoring — measure completeness, consistency, and coverage of incident evidence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_REQUIRED_FIELDS = {"timestamp", "action"}
_RECOMMENDED_FIELDS = {"agent_id", "type", "src_ip", "dst_ip", "status"}
_ENRICHMENT_FIELDS = {"severity", "category", "description", "reason", "tool", "target"}


@dataclass
class FieldCoverage:
    field_name: str
    present_count: int
    total_events: int
    coverage_pct: float


@dataclass
class ConsistencyCheck:
    check_name: str
    passed: bool
    detail: str


@dataclass
class QualityScore:
    completeness: float
    consistency: float
    coverage: float
    timeliness: float
    overall: float
    grade: str


@dataclass
class EvidenceQualityReport:
    total_events: int
    field_coverage: list[FieldCoverage]
    consistency_checks: list[ConsistencyCheck]
    quality_score: QualityScore
    recommendations: list[str]
    summary: str


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events


def analyze(evidence_dir: str | Path) -> EvidenceQualityReport:
    events = _load_events(Path(evidence_dir))

    if not events:
        return EvidenceQualityReport(
            total_events=0,
            field_coverage=[],
            consistency_checks=[],
            quality_score=QualityScore(0, 0, 0, 0, 0, "F"),
            recommendations=["No events found. Ensure evidence files contain valid JSONL data."],
            summary="No events to analyze.",
        )

    all_fields = _REQUIRED_FIELDS | _RECOMMENDED_FIELDS | _ENRICHMENT_FIELDS
    coverage_list: list[FieldCoverage] = []
    for fld in sorted(all_fields):
        present = sum(1 for ev in events if fld in ev and ev[fld])
        coverage_list.append(FieldCoverage(
            field_name=fld,
            present_count=present,
            total_events=len(events),
            coverage_pct=round(present / len(events) * 100, 1),
        ))

    required_score = _score_required_fields(events)
    recommended_score = _score_recommended_fields(events)
    completeness = round(0.6 * required_score + 0.4 * recommended_score, 2)

    checks = _run_consistency_checks(events)
    passed = sum(1 for c in checks if c.passed)
    consistency = round(passed / len(checks), 2) if checks else 1.0

    unique_fields = set()
    for ev in events:
        unique_fields.update(ev.keys())
    breadth = len(unique_fields & all_fields) / len(all_fields)
    coverage = round(breadth, 2)

    timeliness = _score_timeliness(events)

    overall = round(0.30 * completeness + 0.25 * consistency + 0.25 * coverage + 0.20 * timeliness, 2)
    grade = _score_to_grade(overall)

    recommendations = _generate_recommendations(events, coverage_list, checks)

    quality = QualityScore(
        completeness=completeness,
        consistency=consistency,
        coverage=coverage,
        timeliness=timeliness,
        overall=overall,
        grade=grade,
    )

    summary = (
        f"{len(events)} events analyzed. "
        f"Quality score: {overall:.0%} ({grade}). "
        f"Completeness: {completeness:.0%}, Consistency: {consistency:.0%}, "
        f"Coverage: {coverage:.0%}, Timeliness: {timeliness:.0%}."
    )

    return EvidenceQualityReport(
        total_events=len(events),
        field_coverage=coverage_list,
        consistency_checks=checks,
        quality_score=quality,
        recommendations=recommendations,
        summary=summary,
    )


def _score_required_fields(events: list[dict]) -> float:
    total = len(events) * len(_REQUIRED_FIELDS)
    if total == 0:
        return 0
    present = sum(1 for ev in events for f in _REQUIRED_FIELDS if f in ev and ev[f])
    return present / total


def _score_recommended_fields(events: list[dict]) -> float:
    total = len(events) * len(_RECOMMENDED_FIELDS)
    if total == 0:
        return 0
    present = sum(1 for ev in events for f in _RECOMMENDED_FIELDS if f in ev and ev[f])
    return present / total


def _run_consistency_checks(events: list[dict]) -> list[ConsistencyCheck]:
    checks: list[ConsistencyCheck] = []

    ts_events = [ev for ev in events if "timestamp" in ev]
    if len(ts_events) >= 2:
        timestamps = [ev["timestamp"] for ev in ts_events]
        sorted_ts = sorted(timestamps)
        is_ordered = timestamps == sorted_ts
        checks.append(ConsistencyCheck(
            check_name="chronological_order",
            passed=is_ordered,
            detail="Events are in chronological order" if is_ordered else "Events are not chronologically ordered",
        ))

    actions = [ev.get("action", "") for ev in events if ev.get("action")]
    if actions:
        unique_ratio = len(set(actions)) / len(actions)
        diverse = unique_ratio > 0.1
        checks.append(ConsistencyCheck(
            check_name="action_diversity",
            passed=diverse,
            detail=f"Action diversity ratio: {unique_ratio:.2f}" + (" (sufficient)" if diverse else " (too uniform)"),
        ))

    has_agents = [ev for ev in events if ev.get("agent_id")]
    if has_agents:
        agents = set(ev["agent_id"] for ev in has_agents)
        multi = len(agents) > 1
        checks.append(ConsistencyCheck(
            check_name="multi_agent",
            passed=multi,
            detail=f"{len(agents)} unique agent(s) observed",
        ))

    dups = len(events) - len({json.dumps(ev, sort_keys=True) for ev in events})
    no_dups = dups == 0
    checks.append(ConsistencyCheck(
        check_name="no_duplicates",
        passed=no_dups,
        detail=f"{dups} duplicate event(s) found" if dups else "No duplicate events",
    ))

    return checks


def _score_timeliness(events: list[dict]) -> float:
    timestamps = [ev.get("timestamp", "") for ev in events if ev.get("timestamp")]
    if len(timestamps) < 2:
        return 0.5
    try:
        sorted_ts = sorted(timestamps)
        first, last = sorted_ts[0], sorted_ts[-1]
        from datetime import datetime, timezone
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        t0 = datetime.strptime(first, fmt).replace(tzinfo=timezone.utc)
        t1 = datetime.strptime(last, fmt).replace(tzinfo=timezone.utc)
        span_hours = (t1 - t0).total_seconds() / 3600
        if span_hours <= 0:
            return 0.5
        events_per_hour = len(timestamps) / span_hours
        if events_per_hour >= 10:
            return 1.0
        if events_per_hour >= 1:
            return 0.7
        return 0.4
    except (ValueError, TypeError):
        return 0.5


def _score_to_grade(score: float) -> str:
    if score >= 0.9:
        return "A"
    if score >= 0.8:
        return "B"
    if score >= 0.7:
        return "C"
    if score >= 0.6:
        return "D"
    return "F"


def _generate_recommendations(events: list[dict], coverage: list[FieldCoverage], checks: list[ConsistencyCheck]) -> list[str]:
    recs: list[str] = []
    for fc in coverage:
        if fc.field_name in _REQUIRED_FIELDS and fc.coverage_pct < 100:
            recs.append(f"Required field '{fc.field_name}' missing in {100 - fc.coverage_pct:.0f}% of events.")
    for fc in coverage:
        if fc.field_name in _RECOMMENDED_FIELDS and fc.coverage_pct < 50:
            recs.append(f"Recommended field '{fc.field_name}' has low coverage ({fc.coverage_pct:.0f}%).")
    for c in checks:
        if not c.passed:
            recs.append(f"Consistency check '{c.check_name}' failed: {c.detail}")
    return recs[:10]


def format_text(report: EvidenceQualityReport) -> str:
    lines = [
        "Evidence Quality Report",
        "=" * 40,
        f"Events analyzed:  {report.total_events}",
        f"Overall score:    {report.quality_score.overall:.0%} ({report.quality_score.grade})",
        f"Completeness:     {report.quality_score.completeness:.0%}",
        f"Consistency:      {report.quality_score.consistency:.0%}",
        f"Coverage:         {report.quality_score.coverage:.0%}",
        f"Timeliness:       {report.quality_score.timeliness:.0%}",
        "",
    ]

    if report.field_coverage:
        lines.append("Field Coverage")
        lines.append("-" * 30)
        for fc in report.field_coverage:
            bar = "#" * int(fc.coverage_pct / 10)
            lines.append(f"  {fc.field_name:20s} {fc.coverage_pct:5.1f}% [{bar:<10s}]")
        lines.append("")

    if report.consistency_checks:
        lines.append("Consistency Checks")
        lines.append("-" * 30)
        for c in report.consistency_checks:
            status = "PASS" if c.passed else "FAIL"
            lines.append(f"  [{status}] {c.check_name}: {c.detail}")
        lines.append("")

    if report.recommendations:
        lines.append("Recommendations")
        lines.append("-" * 30)
        for r in report.recommendations:
            lines.append(f"  - {r}")
        lines.append("")

    lines.append(report.summary)
    return "\n".join(lines)


def format_json(report: EvidenceQualityReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
