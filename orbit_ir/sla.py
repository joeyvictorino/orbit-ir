"""Response time SLA measurement — measure incident response against configurable time targets."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_DEFAULT_SLA = {
    "time_to_acknowledge_minutes": 15,
    "time_to_contain_minutes": 60,
    "time_to_resolve_minutes": 240,
    "time_to_notify_minutes": 30,
}

_ACKNOWLEDGE_INDICATORS = {"acknowledge", "ack", "triage", "assign", "investigate", "review", "assess"}
_CONTAIN_INDICATORS = {"contain", "isolate", "block", "quarantine", "disable", "revoke", "suspend", "mitigate"}
_RESOLVE_INDICATORS = {"resolve", "remediate", "fix", "restore", "recover", "close", "patch", "clean"}
_NOTIFY_INDICATORS = {"notify", "alert", "escalate", "page", "email", "report", "communicate"}
_DETECT_INDICATORS = {"detect", "alert", "anomaly", "finding", "flag", "warn", "trigger"}


@dataclass
class SLAMeasurement:
    metric: str
    target_minutes: float
    actual_minutes: float | None
    met: bool | None
    margin_minutes: float | None
    assessment: str
    first_event_time: str
    trigger_event_time: str


@dataclass
class IncidentSLA:
    incident_id: str
    detection_time: str
    measurements: list[SLAMeasurement]
    overall_compliance: bool
    compliance_score: float


@dataclass
class SLAReport:
    total_events: int
    incidents_measured: int
    sla_targets: dict[str, float]
    incidents: list[IncidentSLA]
    overall_compliance_rate: float
    average_response_minutes: dict[str, float]
    worst_violations: list[SLAMeasurement]
    summary: str


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


def _classify_response(ev: dict[str, Any]) -> str | None:
    text = " ".join(
        str(v).lower()
        for k, v in ev.items()
        if k in ("type", "action", "effect", "actual_tool", "category", "description", "reason", "status")
    )
    if any(w in text for w in _RESOLVE_INDICATORS):
        return "resolve"
    if any(w in text for w in _CONTAIN_INDICATORS):
        return "contain"
    if any(w in text for w in _NOTIFY_INDICATORS):
        return "notify"
    if any(w in text for w in _ACKNOWLEDGE_INDICATORS):
        return "acknowledge"
    if any(w in text for w in _DETECT_INDICATORS):
        return "detect"
    return None


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


def analyze(
    evidence_dir: str | Path,
    sla_targets: dict[str, float] | None = None,
) -> SLAReport:
    if sla_targets is None:
        sla_targets = dict(_DEFAULT_SLA)

    events = _load_events(Path(evidence_dir))

    timestamped: list[tuple[datetime, dict[str, Any]]] = []
    for ev in events:
        ts_str = ev.get("timestamp", "")
        if not ts_str:
            continue
        dt = _parse_ts(ts_str)
        if dt:
            timestamped.append((dt, ev))

    if not timestamped:
        return SLAReport(
            total_events=0,
            incidents_measured=0,
            sla_targets=sla_targets,
            incidents=[],
            overall_compliance_rate=1.0,
            average_response_minutes={},
            worst_violations=[],
            summary="No timestamped events found.",
        )

    timestamped.sort(key=lambda x: x[0])

    phase_events: dict[str, list[tuple[datetime, dict[str, Any]]]] = {
        "detect": [],
        "acknowledge": [],
        "contain": [],
        "resolve": [],
        "notify": [],
    }

    for dt, ev in timestamped:
        phase = _classify_response(ev)
        if phase and phase in phase_events:
            phase_events[phase].append((dt, ev))

    detection_times = phase_events["detect"]
    if not detection_times:
        detection_times = [(timestamped[0][0], timestamped[0][1])]

    incidents: list[IncidentSLA] = []
    all_measurements: list[SLAMeasurement] = []
    response_times: dict[str, list[float]] = {}

    for i, (detect_dt, detect_ev) in enumerate(detection_times):
        incident_id = detect_ev.get("incident_id", f"incident-{i+1}")
        measurements: list[SLAMeasurement] = []

        metric_map = {
            "time_to_acknowledge_minutes": ("acknowledge", phase_events["acknowledge"]),
            "time_to_contain_minutes": ("contain", phase_events["contain"]),
            "time_to_resolve_minutes": ("resolve", phase_events["resolve"]),
            "time_to_notify_minutes": ("notify", phase_events["notify"]),
        }

        for sla_key, (phase_name, phase_evts) in metric_map.items():
            target = sla_targets.get(sla_key)
            if target is None:
                continue

            response_dt = None
            for evt_dt, _ in phase_evts:
                if evt_dt >= detect_dt:
                    response_dt = evt_dt
                    break

            if response_dt is not None:
                actual_min = (response_dt - detect_dt).total_seconds() / 60
                met = actual_min <= target
                margin = target - actual_min
                assessment = "met" if met else "violated"
                if met and margin > target * 0.5:
                    assessment = "comfortable"
                elif not met and actual_min > target * 2:
                    assessment = "critical_violation"

                m = SLAMeasurement(
                    metric=f"Time to {phase_name}",
                    target_minutes=target,
                    actual_minutes=round(actual_min, 1),
                    met=met,
                    margin_minutes=round(margin, 1),
                    assessment=assessment,
                    first_event_time=detect_dt.isoformat(),
                    trigger_event_time=response_dt.isoformat(),
                )
            else:
                m = SLAMeasurement(
                    metric=f"Time to {phase_name}",
                    target_minutes=target,
                    actual_minutes=None,
                    met=None,
                    margin_minutes=None,
                    assessment="no_data",
                    first_event_time=detect_dt.isoformat(),
                    trigger_event_time="",
                )

            measurements.append(m)
            all_measurements.append(m)

            if m.actual_minutes is not None:
                response_times.setdefault(m.metric, []).append(m.actual_minutes)

        measured = [m for m in measurements if m.met is not None]
        compliant = all(m.met for m in measured) if measured else True
        score = sum(1 for m in measured if m.met) / len(measured) if measured else 1.0

        incidents.append(IncidentSLA(
            incident_id=incident_id,
            detection_time=detect_dt.isoformat(),
            measurements=measurements,
            overall_compliance=compliant,
            compliance_score=round(score, 2),
        ))

    compliant_count = sum(1 for inc in incidents if inc.overall_compliance)
    compliance_rate = compliant_count / len(incidents) if incidents else 1.0

    avg_response = {
        metric: round(sum(times) / len(times), 1)
        for metric, times in response_times.items()
    }

    violations = [m for m in all_measurements if m.met is False]
    violations.sort(key=lambda x: -(x.actual_minutes or 0))
    worst = violations[:5]

    met_count = sum(1 for m in all_measurements if m.met is True)
    violated_count = sum(1 for m in all_measurements if m.met is False)
    summary = (
        f"{len(incidents)} incident(s) measured. "
        f"{met_count} SLA(s) met, {violated_count} violated. "
        f"Compliance rate: {compliance_rate:.0%}."
    )

    return SLAReport(
        total_events=len(timestamped),
        incidents_measured=len(incidents),
        sla_targets=sla_targets,
        incidents=incidents,
        overall_compliance_rate=round(compliance_rate, 2),
        average_response_minutes=avg_response,
        worst_violations=worst,
        summary=summary,
    )


def format_text(report: SLAReport) -> str:
    lines = [
        "Response Time SLA Report",
        "=" * 40,
        f"Events analyzed:       {report.total_events}",
        f"Incidents measured:    {report.incidents_measured}",
        f"Compliance rate:       {report.overall_compliance_rate:.0%}",
        "",
    ]

    if report.sla_targets:
        lines.append("SLA Targets")
        lines.append("-" * 30)
        for key, val in sorted(report.sla_targets.items()):
            label = key.replace("_", " ").replace(" minutes", "").title()
            lines.append(f"  {label:25s} {val:.0f} min")
        lines.append("")

    if report.average_response_minutes:
        lines.append("Average Response Times")
        lines.append("-" * 30)
        for metric, avg in sorted(report.average_response_minutes.items()):
            lines.append(f"  {metric:25s} {avg:.1f} min")
        lines.append("")

    for inc in report.incidents:
        lines.append(f"Incident: {inc.incident_id}")
        lines.append(f"  Detection: {inc.detection_time}")
        lines.append(f"  Compliance: {'PASS' if inc.overall_compliance else 'FAIL'} ({inc.compliance_score:.0%})")
        for m in inc.measurements:
            if m.actual_minutes is not None:
                status = "MET" if m.met else "VIOLATED"
                lines.append(f"    {m.metric:25s} {m.actual_minutes:>8.1f} min / {m.target_minutes:.0f} min [{status}]")
            else:
                lines.append(f"    {m.metric:25s} {'N/A':>8s}     / {m.target_minutes:.0f} min [NO DATA]")
        lines.append("")

    if report.worst_violations:
        lines.append("Worst Violations")
        lines.append("-" * 30)
        for m in report.worst_violations:
            overage = (m.actual_minutes or 0) - m.target_minutes
            lines.append(f"  {m.metric}: {m.actual_minutes:.1f} min (target {m.target_minutes:.0f} min, +{overage:.1f} min over)")
        lines.append("")

    lines.append(report.summary)
    lines.append("")
    return "\n".join(lines)


def format_json(report: SLAReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
