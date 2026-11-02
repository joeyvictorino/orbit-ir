"""Incident response timing analysis for agent evidence.

Measures detection-to-action latency, action duration, inter-action
gaps, and total incident response time across agent event logs.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ResponseTiming:
    timing_id: str
    agent_id: str
    incident_id: str
    detection_time: str
    first_action_time: str
    last_action_time: str
    detection_to_action_seconds: float
    total_duration_seconds: float
    action_count: int
    inter_action_gaps: list[float] = field(default_factory=list)


@dataclass
class ResponseTimeSummary:
    total_incidents: int
    avg_detection_to_action: float
    median_detection_to_action: float
    p95_detection_to_action: float
    avg_total_duration: float
    fastest_response: float
    slowest_response: float
    agents_analyzed: int


@dataclass
class ResponseTimeReport:
    timings: list[ResponseTiming]
    summary: ResponseTimeSummary


_DETECT_KEYWORDS = ("detect", "alert", "alarm", "trigger", "anomaly", "violation")
_ACTION_KEYWORDS = ("action", "respond", "mitigate", "block", "remediate", "isolate", "contain", "quarantine")


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _is_detection(ev: dict, detection_types: list[str] | None) -> bool:
    et = (ev.get("event_type") or ev.get("type") or "").lower()
    if detection_types:
        return any(dt.lower() in et for dt in detection_types)
    return any(kw in et for kw in _DETECT_KEYWORDS)


def _is_action(ev: dict) -> bool:
    et = (ev.get("event_type") or ev.get("type") or "").lower()
    return any(kw in et for kw in _ACTION_KEYWORDS)


def analyze_response_times(
    events: list[dict[str, Any]],
    detection_types: list[str] | None = None,
) -> ResponseTimeReport:
    by_agent: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent_id", "")
        ts = _parse_ts(ev.get("timestamp", ""))
        if ts and agent:
            by_agent[agent].append((ts, ev))

    timings: list[ResponseTiming] = []
    timing_counter = 0

    for agent in sorted(by_agent):
        agent_events = sorted(by_agent[agent], key=lambda x: x[0])

        detections: list[tuple[datetime, dict]] = []
        actions: list[tuple[datetime, dict]] = []
        for ts, ev in agent_events:
            if _is_detection(ev, detection_types):
                detections.append((ts, ev))
            elif _is_action(ev):
                actions.append((ts, ev))

        for det_ts, det_ev in detections:
            incident_actions = [(ts, ev) for ts, ev in actions if ts >= det_ts]
            if not incident_actions:
                continue

            timing_counter += 1
            first_action_ts = incident_actions[0][0]
            last_action_ts = incident_actions[-1][0]
            d2a = (first_action_ts - det_ts).total_seconds()
            total = (last_action_ts - det_ts).total_seconds()

            gaps: list[float] = []
            for i in range(1, len(incident_actions)):
                gap = (incident_actions[i][0] - incident_actions[i - 1][0]).total_seconds()
                gaps.append(round(gap, 2))

            timings.append(ResponseTiming(
                timing_id=f"RT-{timing_counter:03d}",
                agent_id=agent,
                incident_id=det_ev.get("incident_id", f"INC-{timing_counter:03d}"),
                detection_time=det_ev.get("timestamp", ""),
                first_action_time=incident_actions[0][1].get("timestamp", ""),
                last_action_time=incident_actions[-1][1].get("timestamp", ""),
                detection_to_action_seconds=round(d2a, 2),
                total_duration_seconds=round(total, 2),
                action_count=len(incident_actions),
                inter_action_gaps=gaps,
            ))

    d2a_values = [t.detection_to_action_seconds for t in timings]
    if d2a_values:
        d2a_sorted = sorted(d2a_values)
        p95_idx = int(len(d2a_sorted) * 0.95)
        if p95_idx >= len(d2a_sorted):
            p95_idx = len(d2a_sorted) - 1
        summary = ResponseTimeSummary(
            total_incidents=len(timings),
            avg_detection_to_action=round(statistics.mean(d2a_values), 2),
            median_detection_to_action=round(statistics.median(d2a_values), 2),
            p95_detection_to_action=round(d2a_sorted[p95_idx], 2),
            avg_total_duration=round(statistics.mean([t.total_duration_seconds for t in timings]), 2),
            fastest_response=round(min(d2a_values), 2),
            slowest_response=round(max(d2a_values), 2),
            agents_analyzed=len({t.agent_id for t in timings}),
        )
    else:
        summary = ResponseTimeSummary(
            total_incidents=0,
            avg_detection_to_action=0.0,
            median_detection_to_action=0.0,
            p95_detection_to_action=0.0,
            avg_total_duration=0.0,
            fastest_response=0.0,
            slowest_response=0.0,
            agents_analyzed=0,
        )

    return ResponseTimeReport(timings=timings, summary=summary)


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    transcripts = evidence_dir / "transcripts.jsonl"
    if transcripts.exists():
        for line in transcripts.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def format_text(report: ResponseTimeReport) -> str:
    lines: list[str] = []
    lines.append("Incident Response Timing Analysis")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total incidents:        {s.total_incidents}")
    lines.append(f"  Avg detection-to-action: {s.avg_detection_to_action:.1f}s")
    lines.append(f"  Median D2A:             {s.median_detection_to_action:.1f}s")
    lines.append(f"  P95 D2A:                {s.p95_detection_to_action:.1f}s")
    lines.append(f"  Avg total duration:     {s.avg_total_duration:.1f}s")
    lines.append(f"  Fastest response:       {s.fastest_response:.1f}s")
    lines.append(f"  Slowest response:       {s.slowest_response:.1f}s")
    lines.append(f"  Agents analyzed:        {s.agents_analyzed}")
    lines.append("")

    for t in report.timings:
        lines.append(f"  {t.timing_id}: {t.agent_id} / {t.incident_id}")
        lines.append(f"    Detection-to-action: {t.detection_to_action_seconds:.1f}s")
        lines.append(f"    Total duration:      {t.total_duration_seconds:.1f}s")
        lines.append(f"    Actions:             {t.action_count}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ResponseTimeReport) -> str:
    data = {
        "timings": [asdict(t) for t in report.timings],
        "summary": asdict(report.summary),
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
