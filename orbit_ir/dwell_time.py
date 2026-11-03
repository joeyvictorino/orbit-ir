"""Dwell-time analysis — measure how long incidents persist before detection and response."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


_DEFAULT_BENCHMARKS = {
    "time_to_detect_days": 200,
    "time_to_respond_days": 70,
    "total_duration_days": 270,
}

_RECON_INDICATORS = {"scan", "enumerate", "list", "probe", "discover", "reconnaissance"}
_EXPLOIT_INDICATORS = {"exploit", "inject", "execute", "escalate", "bypass", "compromise"}
_PERSIST_INDICATORS = {"persist", "backdoor", "implant", "cron", "scheduled", "install"}
_DETECT_INDICATORS = {"detect", "alert", "anomaly", "finding", "flag", "warn"}
_RESPOND_INDICATORS = {"respond", "remediate", "block", "isolate", "revoke", "contain", "mitigate"}


@dataclass
class PhaseBreakdown:
    recon_seconds: float = 0.0
    exploitation_seconds: float = 0.0
    persistence_seconds: float = 0.0
    detection_seconds: float = 0.0
    response_seconds: float = 0.0


@dataclass
class BenchmarkComparison:
    metric: str
    actual_days: float
    benchmark_days: float
    ratio: float
    assessment: str


@dataclass
class DwellTimeReport:
    first_event: str
    last_event: str
    total_duration_seconds: float
    time_to_detect_seconds: float | None
    time_to_respond_seconds: float | None
    phase_breakdown: PhaseBreakdown
    benchmarks: list[BenchmarkComparison]
    bottleneck: str
    event_count: int


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


def _classify_event(ev: dict[str, Any]) -> str | None:
    text = " ".join(
        str(v).lower()
        for k, v in ev.items()
        if k in ("type", "effect", "actual_tool", "action", "category", "description", "reason")
    )
    if any(w in text for w in _RESPOND_INDICATORS):
        return "response"
    if any(w in text for w in _DETECT_INDICATORS):
        return "detection"
    if any(w in text for w in _PERSIST_INDICATORS):
        return "persistence"
    if any(w in text for w in _EXPLOIT_INDICATORS):
        return "exploitation"
    if any(w in text for w in _RECON_INDICATORS):
        return "recon"
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
    benchmarks: dict[str, float] | None = None,
) -> DwellTimeReport:
    if benchmarks is None:
        benchmarks = dict(_DEFAULT_BENCHMARKS)

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
        return DwellTimeReport(
            first_event="",
            last_event="",
            total_duration_seconds=0,
            time_to_detect_seconds=None,
            time_to_respond_seconds=None,
            phase_breakdown=PhaseBreakdown(),
            benchmarks=[],
            bottleneck="no timestamped events",
            event_count=0,
        )

    timestamped.sort(key=lambda x: x[0])
    first_dt = timestamped[0][0]
    last_dt = timestamped[-1][0]
    total_sec = (last_dt - first_dt).total_seconds()

    phase_events: dict[str, list[datetime]] = {
        "recon": [],
        "exploitation": [],
        "persistence": [],
        "detection": [],
        "response": [],
    }
    for dt, ev in timestamped:
        phase = _classify_event(ev)
        if phase and phase in phase_events:
            phase_events[phase].append(dt)

    first_compromise = None
    for phase in ("exploitation", "persistence"):
        if phase_events[phase]:
            candidate = phase_events[phase][0]
            if first_compromise is None or candidate < first_compromise:
                first_compromise = candidate

    first_detection = phase_events["detection"][0] if phase_events["detection"] else None
    first_response = phase_events["response"][0] if phase_events["response"] else None

    time_to_detect: float | None = None
    if first_compromise and first_detection:
        time_to_detect = (first_detection - first_compromise).total_seconds()

    time_to_respond: float | None = None
    if first_detection and first_response:
        time_to_respond = (first_response - first_detection).total_seconds()

    breakdown = PhaseBreakdown()
    for phase_name, timestamps in phase_events.items():
        if len(timestamps) >= 2:
            dur = (timestamps[-1] - timestamps[0]).total_seconds()
        elif len(timestamps) == 1:
            dur = 0.0
        else:
            dur = 0.0
        setattr(breakdown, f"{phase_name}_seconds", dur)

    bench_comparisons: list[BenchmarkComparison] = []
    metric_map = {
        "time_to_detect_days": ("Time to Detect", time_to_detect),
        "time_to_respond_days": ("Time to Respond", time_to_respond),
        "total_duration_days": ("Total Duration", total_sec),
    }
    for key, (label, actual_sec) in metric_map.items():
        if actual_sec is not None and key in benchmarks:
            actual_days = actual_sec / 86400
            bench_days = benchmarks[key]
            ratio = actual_days / bench_days if bench_days > 0 else 0
            if ratio <= 0.5:
                assessment = "excellent"
            elif ratio <= 1.0:
                assessment = "good"
            elif ratio <= 2.0:
                assessment = "concerning"
            else:
                assessment = "critical"
            bench_comparisons.append(BenchmarkComparison(
                metric=label,
                actual_days=round(actual_days, 2),
                benchmark_days=bench_days,
                ratio=round(ratio, 3),
                assessment=assessment,
            ))

    bottleneck = "unknown"
    phase_durations = {
        "recon": breakdown.recon_seconds,
        "exploitation": breakdown.exploitation_seconds,
        "persistence": breakdown.persistence_seconds,
        "detection": breakdown.detection_seconds,
        "response": breakdown.response_seconds,
    }
    if any(v > 0 for v in phase_durations.values()):
        bottleneck = max(phase_durations, key=phase_durations.get)  # type: ignore[arg-type]

    return DwellTimeReport(
        first_event=timestamped[0][0].isoformat(),
        last_event=timestamped[-1][0].isoformat(),
        total_duration_seconds=total_sec,
        time_to_detect_seconds=time_to_detect,
        time_to_respond_seconds=time_to_respond,
        phase_breakdown=breakdown,
        benchmarks=bench_comparisons,
        bottleneck=bottleneck,
        event_count=len(timestamped),
    )


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def format_text(report: DwellTimeReport) -> str:
    lines = [
        "Dwell Time Analysis",
        "=" * 40,
        f"Events analyzed:    {report.event_count}",
        f"First event:        {report.first_event}",
        f"Last event:         {report.last_event}",
        f"Total duration:     {_fmt_duration(report.total_duration_seconds)}",
        "",
    ]
    if report.time_to_detect_seconds is not None:
        lines.append(f"Time to detect:     {_fmt_duration(report.time_to_detect_seconds)}")
    if report.time_to_respond_seconds is not None:
        lines.append(f"Time to respond:    {_fmt_duration(report.time_to_respond_seconds)}")

    lines.extend(["", "Phase Breakdown", "-" * 30])
    pb = report.phase_breakdown
    for name, val in [
        ("Reconnaissance", pb.recon_seconds),
        ("Exploitation", pb.exploitation_seconds),
        ("Persistence", pb.persistence_seconds),
        ("Detection", pb.detection_seconds),
        ("Response", pb.response_seconds),
    ]:
        lines.append(f"  {name:20s} {_fmt_duration(val)}")

    if report.benchmarks:
        lines.extend(["", "Benchmark Comparison", "-" * 30])
        for b in report.benchmarks:
            lines.append(
                f"  {b.metric:20s} {b.actual_days:>8.1f}d vs {b.benchmark_days:.0f}d benchmark  "
                f"({b.ratio:.1f}x) [{b.assessment}]"
            )

    lines.extend(["", f"Bottleneck phase:   {report.bottleneck}", ""])
    return "\n".join(lines)


def format_json(report: DwellTimeReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
