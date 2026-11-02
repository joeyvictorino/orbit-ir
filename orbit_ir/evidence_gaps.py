"""Evidence gap detection — identify time windows with no recorded events."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass
class Gap:
    start: str
    end: str
    duration_seconds: float
    preceding_agent: str
    following_agent: str
    preceding_action: str
    following_action: str


@dataclass
class GapMetrics:
    total_events: int = 0
    total_gaps: int = 0
    max_gap_seconds: float = 0.0
    mean_gap_seconds: float = 0.0
    median_gap_seconds: float = 0.0
    coverage_pct: float = 100.0
    gap_score: float = 1.0
    grade: str = "A"


@dataclass
class GapReport:
    metrics: GapMetrics = field(default_factory=GapMetrics)
    gaps: list[Gap] = field(default_factory=list)
    timeline_start: str = ""
    timeline_end: str = ""


_ISO_FMTS = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]


def _parse_ts(s: str) -> datetime | None:
    for fmt in _ISO_FMTS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    for p in sorted(evidence_dir.iterdir()):
        if p.suffix == ".jsonl":
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def analyze(evidence_dir: Path, gap_threshold_seconds: float = 300.0) -> GapReport:
    events = _load_events(evidence_dir)
    if not events:
        return GapReport()

    timestamped = []
    for e in events:
        ts = _parse_ts(e.get("timestamp", ""))
        if ts:
            timestamped.append((ts, e))

    if len(timestamped) < 2:
        return GapReport(
            metrics=GapMetrics(total_events=len(events)),
            timeline_start=events[0].get("timestamp", "") if events else "",
            timeline_end=events[-1].get("timestamp", "") if events else "",
        )

    timestamped.sort(key=lambda x: x[0])
    gaps: list[Gap] = []
    durations: list[float] = []

    for i in range(1, len(timestamped)):
        prev_ts, prev_ev = timestamped[i - 1]
        curr_ts, curr_ev = timestamped[i]
        delta = (curr_ts - prev_ts).total_seconds()
        durations.append(delta)
        if delta >= gap_threshold_seconds:
            gaps.append(Gap(
                start=prev_ev.get("timestamp", ""),
                end=curr_ev.get("timestamp", ""),
                duration_seconds=round(delta, 1),
                preceding_agent=prev_ev.get("agent_id", "unknown"),
                following_agent=curr_ev.get("agent_id", "unknown"),
                preceding_action=prev_ev.get("action", ""),
                following_action=curr_ev.get("action", ""),
            ))

    total_span = (timestamped[-1][0] - timestamped[0][0]).total_seconds()
    gap_time = sum(g.duration_seconds for g in gaps)
    coverage = 100.0 * (1 - gap_time / max(1.0, total_span)) if total_span > 0 else 100.0

    sorted_durations = sorted(durations)
    median = sorted_durations[len(sorted_durations) // 2] if sorted_durations else 0

    score = min(1.0, coverage / 100.0)
    if gaps:
        score *= max(0.0, 1.0 - len(gaps) / max(1, len(timestamped)) * 2)

    metrics = GapMetrics(
        total_events=len(events),
        total_gaps=len(gaps),
        max_gap_seconds=round(max(durations) if durations else 0, 1),
        mean_gap_seconds=round(sum(durations) / len(durations) if durations else 0, 1),
        median_gap_seconds=round(median, 1),
        coverage_pct=round(coverage, 1),
        gap_score=round(score, 2),
        grade=_score_to_grade(score),
    )

    return GapReport(
        metrics=metrics,
        gaps=sorted(gaps, key=lambda g: g.duration_seconds, reverse=True),
        timeline_start=timestamped[0][1].get("timestamp", ""),
        timeline_end=timestamped[-1][1].get("timestamp", ""),
    )


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


def format_text(report: GapReport) -> str:
    m = report.metrics
    lines = [
        "Evidence Gap Analysis",
        "=" * 40,
        f"Total events:        {m.total_events}",
        f"Timeline:            {report.timeline_start} to {report.timeline_end}",
        f"Gaps detected:       {m.total_gaps}",
        f"Max gap:             {m.max_gap_seconds:.1f}s",
        f"Mean inter-event:    {m.mean_gap_seconds:.1f}s",
        f"Median inter-event:  {m.median_gap_seconds:.1f}s",
        f"Coverage:            {m.coverage_pct:.1f}%",
        f"Gap score:           {m.gap_score:.2f} ({m.grade})",
        "",
    ]

    if report.gaps:
        lines.append("Detected gaps (largest first):")
        for g in report.gaps[:15]:
            lines.append(
                f"  {g.start} -> {g.end} ({g.duration_seconds:.0f}s) "
                f"{g.preceding_agent}:{g.preceding_action} -> {g.following_agent}:{g.following_action}"
            )
        if len(report.gaps) > 15:
            lines.append(f"  ... and {len(report.gaps) - 15} more")

    return "\n".join(lines) + "\n"


def format_json(report: GapReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str) + "\n"
