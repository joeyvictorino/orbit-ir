"""Response effectiveness metrics — measure how well incident response actions performed."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_ACTION_CATEGORIES = {
    "detection": {"detect", "alert", "anomaly", "flag", "warn", "trigger", "monitor"},
    "containment": {"contain", "isolate", "block", "quarantine", "disable", "revoke", "suspend"},
    "eradication": {"eradicate", "remove", "delete", "clean", "patch", "fix", "remediate"},
    "recovery": {"recover", "restore", "rebuild", "redeploy", "restart", "resume"},
    "communication": {"notify", "alert", "escalate", "report", "communicate", "page"},
    "investigation": {"investigate", "analyze", "triage", "assess", "review", "examine"},
}


@dataclass
class ActionMetric:
    category: str
    action_count: int
    unique_actions: int
    first_action_time: str
    last_action_time: str
    span_minutes: float


@dataclass
class EffectivenessScore:
    response_breadth: float
    action_density: float
    phase_coverage: float
    escalation_speed: float
    overall: float
    grade: str


@dataclass
class ResponseEffectivenessReport:
    total_events: int
    total_response_actions: int
    action_metrics: list[ActionMetric]
    phases_covered: list[str]
    phases_missing: list[str]
    effectiveness_score: EffectivenessScore
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


def _parse_ts(ts_str: str) -> datetime | None:
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _classify_action(ev: dict[str, Any]) -> str | None:
    text = " ".join(
        str(v).lower()
        for k, v in ev.items()
        if k in ("type", "action", "effect", "category", "description", "status")
    )
    for category, keywords in _ACTION_CATEGORIES.items():
        if any(w in text for w in keywords):
            return category
    return None


def analyze(evidence_dir: str | Path) -> ResponseEffectivenessReport:
    events = _load_events(Path(evidence_dir))

    if not events:
        return ResponseEffectivenessReport(
            total_events=0,
            total_response_actions=0,
            action_metrics=[],
            phases_covered=[],
            phases_missing=list(_ACTION_CATEGORIES.keys()),
            effectiveness_score=EffectivenessScore(0, 0, 0, 0, 0, "F"),
            recommendations=["No events found."],
            summary="No events to analyze.",
        )

    categorized: dict[str, list[tuple[datetime | None, dict]]] = {cat: [] for cat in _ACTION_CATEGORIES}
    response_count = 0

    for ev in events:
        cat = _classify_action(ev)
        if cat:
            ts = _parse_ts(ev.get("timestamp", ""))
            categorized[cat].append((ts, ev))
            response_count += 1

    metrics: list[ActionMetric] = []
    phases_covered: list[str] = []
    phases_missing: list[str] = []

    for cat, cat_events in categorized.items():
        if not cat_events:
            phases_missing.append(cat)
            continue
        phases_covered.append(cat)

        timed = [(ts, ev) for ts, ev in cat_events if ts is not None]
        timed.sort(key=lambda x: x[0])

        unique_actions = set()
        for _, ev in cat_events:
            action_text = ev.get("action", ev.get("type", ""))
            if action_text:
                unique_actions.add(str(action_text).lower())

        first_time = timed[0][0].isoformat() if timed else ""
        last_time = timed[-1][0].isoformat() if timed else ""
        span = 0.0
        if len(timed) >= 2:
            span = round((timed[-1][0] - timed[0][0]).total_seconds() / 60, 1)

        metrics.append(ActionMetric(
            category=cat,
            action_count=len(cat_events),
            unique_actions=len(unique_actions),
            first_action_time=first_time,
            last_action_time=last_time,
            span_minutes=span,
        ))

    breadth = len(phases_covered) / len(_ACTION_CATEGORIES) if _ACTION_CATEGORIES else 0
    density = min(response_count / max(len(events), 1), 1.0)
    phase_cov = breadth
    escalation = _score_escalation(categorized)

    overall = round(0.30 * breadth + 0.25 * density + 0.25 * phase_cov + 0.20 * escalation, 2)
    grade = _score_to_grade(overall)

    score = EffectivenessScore(
        response_breadth=round(breadth, 2),
        action_density=round(density, 2),
        phase_coverage=round(phase_cov, 2),
        escalation_speed=round(escalation, 2),
        overall=overall,
        grade=grade,
    )

    recommendations = _generate_recommendations(phases_missing, metrics, events)

    summary = (
        f"{len(events)} events, {response_count} response actions. "
        f"Phases covered: {len(phases_covered)}/{len(_ACTION_CATEGORIES)}. "
        f"Effectiveness: {overall:.0%} ({grade})."
    )

    return ResponseEffectivenessReport(
        total_events=len(events),
        total_response_actions=response_count,
        action_metrics=metrics,
        phases_covered=phases_covered,
        phases_missing=phases_missing,
        effectiveness_score=score,
        recommendations=recommendations,
        summary=summary,
    )


def _score_escalation(categorized: dict[str, list[tuple[datetime | None, dict]]]) -> float:
    ordered_phases = ["detection", "investigation", "containment", "eradication", "recovery"]
    first_times: dict[str, datetime] = {}
    for phase in ordered_phases:
        timed = [(ts, ev) for ts, ev in categorized.get(phase, []) if ts]
        if timed:
            timed.sort(key=lambda x: x[0])
            first_times[phase] = timed[0][0]

    if len(first_times) < 2:
        return 0.5

    phases_in_order = [p for p in ordered_phases if p in first_times]
    in_order = all(
        first_times[phases_in_order[i]] <= first_times[phases_in_order[i + 1]]
        for i in range(len(phases_in_order) - 1)
    )
    return 1.0 if in_order else 0.3


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


def _generate_recommendations(missing: list[str], metrics: list[ActionMetric], events: list[dict]) -> list[str]:
    recs: list[str] = []
    for phase in missing:
        recs.append(f"No {phase} actions detected. Consider adding {phase} steps to your response plan.")
    for m in metrics:
        if m.unique_actions <= 1 and m.action_count > 3:
            recs.append(f"Phase '{m.category}' has {m.action_count} actions but only {m.unique_actions} unique type(s).")
    return recs[:10]


def format_text(report: ResponseEffectivenessReport) -> str:
    lines = [
        "Response Effectiveness Report",
        "=" * 40,
        f"Events analyzed:      {report.total_events}",
        f"Response actions:     {report.total_response_actions}",
        f"Overall score:        {report.effectiveness_score.overall:.0%} ({report.effectiveness_score.grade})",
        f"Response breadth:     {report.effectiveness_score.response_breadth:.0%}",
        f"Action density:       {report.effectiveness_score.action_density:.0%}",
        f"Phase coverage:       {report.effectiveness_score.phase_coverage:.0%}",
        f"Escalation speed:     {report.effectiveness_score.escalation_speed:.0%}",
        "",
    ]

    if report.phases_covered:
        lines.append(f"Phases covered:  {', '.join(report.phases_covered)}")
    if report.phases_missing:
        lines.append(f"Phases missing:  {', '.join(report.phases_missing)}")
    lines.append("")

    if report.action_metrics:
        lines.append("Action Metrics")
        lines.append("-" * 30)
        for m in report.action_metrics:
            lines.append(f"  {m.category:20s} {m.action_count} actions ({m.unique_actions} unique), span={m.span_minutes:.1f}min")
        lines.append("")

    if report.recommendations:
        lines.append("Recommendations")
        lines.append("-" * 30)
        for r in report.recommendations:
            lines.append(f"  - {r}")
        lines.append("")

    lines.append(report.summary)
    return "\n".join(lines)


def format_json(report: ResponseEffectivenessReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
