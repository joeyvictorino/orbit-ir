"""Per-detection impact quantification for agent incidents.

Unlike blast_radius (whole-dataset aggregate), this module scores each
individual detection/anomaly: how many agents it touched, which data
stores were accessed during its time window, the API call volume, and
estimated data volume at risk.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_DATA_STORE_KEYWORDS = (
    "database", "db", "redis", "postgres", "mysql", "mongo", "s3",
    "bucket", "storage", "datastore", "table", "collection",
)

_API_EVENT_TYPES = (
    "api_call", "http_request", "tool_call", "function_call",
    "request", "invocation",
)


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


def _parse_ts(val: str | None) -> datetime | None:
    if not val:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(val, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _is_data_store_event(event: dict[str, Any]) -> bool:
    text = json.dumps(event).lower()
    return any(kw in text for kw in _DATA_STORE_KEYWORDS)


def _is_api_event(event: dict[str, Any]) -> bool:
    etype = str(event.get("type", event.get("event_type", ""))).lower()
    if any(kw in etype for kw in _API_EVENT_TYPES):
        return True
    if event.get("tool_name") or event.get("endpoint") or event.get("url"):
        return True
    return False


def _extract_agents(event: dict[str, Any]) -> set[str]:
    agents: set[str] = set()
    for key in ("agent_id", "agent", "src_agent", "dst_agent",
                "from_agent", "to_agent", "sender", "receiver"):
        v = event.get(key)
        if isinstance(v, str) and v:
            agents.add(v)
    return agents


def _estimate_data_volume(events: list[dict[str, Any]]) -> int:
    total = 0
    for e in events:
        size = e.get("size", e.get("bytes", e.get("content_length", 0)))
        if isinstance(size, (int, float)):
            total += int(size)
        elif isinstance(size, str):
            try:
                total += int(size)
            except ValueError:
                pass
        body = e.get("body", e.get("content", e.get("data", "")))
        if isinstance(body, str):
            total += len(body)
    return total


@dataclass
class ImpactAssessment:
    detection_id: str
    detection_type: str
    severity: str
    agents_affected: list[str] = field(default_factory=list)
    data_stores_accessed: list[str] = field(default_factory=list)
    api_calls: int = 0
    estimated_data_bytes: int = 0
    event_count: int = 0
    time_window_seconds: float = 0.0
    impact_score: float = 0.0
    impact_level: str = "low"
    citations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _score_impact(
    agent_count: int,
    store_count: int,
    api_calls: int,
    data_bytes: int,
    severity: str,
) -> tuple[float, str]:
    agent_pts = min(agent_count / 4.0, 1.0) * 2.5
    store_pts = min(store_count / 3.0, 1.0) * 2.5
    api_pts = min(api_calls / 20.0, 1.0) * 2.0
    data_pts = min(data_bytes / (1024 * 1024), 1.0) * 1.0
    sev_pts = _SEVERITY_RANK.get(severity.lower(), 1) / 4.0 * 2.0
    score = round(agent_pts + store_pts + api_pts + data_pts + sev_pts, 2)

    if score >= 7.0:
        level = "critical"
    elif score >= 4.5:
        level = "high"
    elif score >= 2.5:
        level = "medium"
    else:
        level = "low"
    return score, level


class ImpactAnalyzer:
    def __init__(self, window_seconds: float = 300.0) -> None:
        self.window_seconds = window_seconds

    def analyze(
        self,
        results: list[dict[str, Any]],
        evidence_dir: str | Path,
    ) -> list[dict[str, Any]]:
        evidence_dir = Path(evidence_dir)
        events = _load_events(evidence_dir) if evidence_dir.exists() else []
        timed_events = []
        for e in events:
            ts = _parse_ts(e.get("timestamp"))
            if ts:
                timed_events.append((ts, e))
        timed_events.sort(key=lambda x: x[0])

        assessments: list[dict[str, Any]] = []

        for i, det in enumerate(results):
            det_id = det.get("id", det.get("detection_id", f"det-{i}"))
            det_type = det.get("type", det.get("detection_type", det.get("category", "unknown")))
            severity = det.get("severity", det.get("risk_level", "medium"))
            det_ts = _parse_ts(det.get("timestamp"))

            if det_ts and timed_events:
                window_start = det_ts - timedelta(seconds=self.window_seconds / 2)
                window_end = det_ts + timedelta(seconds=self.window_seconds / 2)
                window_events = [
                    e for ts, e in timed_events
                    if window_start <= ts <= window_end
                ]
            else:
                window_events = events

            agents: set[str] = set()
            stores: set[str] = set()
            api_count = 0
            citations: list[dict[str, Any]] = []

            for e in window_events:
                agents.update(_extract_agents(e))
                if _is_data_store_event(e):
                    for key in ("resource", "target", "database", "table",
                                "service", "destination"):
                        v = e.get(key)
                        if isinstance(v, str) and v:
                            stores.add(v)
                if _is_api_event(e):
                    api_count += 1
                src_file = e.get("source_file", e.get("file", ""))
                src_line = e.get("line", e.get("line_number", 0))
                src_ts = e.get("timestamp", "")
                if src_file or src_ts:
                    citations.append({
                        "file": str(src_file),
                        "line": src_line,
                        "timestamp": str(src_ts),
                    })

            if len(citations) > 10:
                citations = citations[:10]

            data_bytes = _estimate_data_volume(window_events)

            time_span = 0.0
            if det_ts and timed_events:
                time_span = self.window_seconds

            score, level = _score_impact(
                len(agents), len(stores), api_count, data_bytes, severity,
            )

            assessment = ImpactAssessment(
                detection_id=str(det_id),
                detection_type=str(det_type),
                severity=str(severity),
                agents_affected=sorted(agents),
                data_stores_accessed=sorted(stores),
                api_calls=api_count,
                estimated_data_bytes=data_bytes,
                event_count=len(window_events),
                time_window_seconds=time_span,
                impact_score=score,
                impact_level=level,
                citations=citations,
            )
            assessments.append(assessment.to_dict())

        return assessments


def analyze_impact(
    results: list[dict[str, Any]],
    evidence_dir: str | Path,
    window_seconds: float = 300.0,
    min_severity: str = "low",
) -> list[dict[str, Any]]:
    min_rank = _SEVERITY_RANK.get(min_severity.lower(), 0)
    filtered = [
        r for r in results
        if _SEVERITY_RANK.get(
            str(r.get("severity", r.get("risk_level", "medium"))).lower(), 1
        ) >= min_rank
    ]
    analyzer = ImpactAnalyzer(window_seconds=window_seconds)
    return analyzer.analyze(filtered, evidence_dir)


def format_impact_text(assessments: list[dict[str, Any]]) -> str:
    if not assessments:
        return "No detections to assess.\n"

    lines: list[str] = []
    lines.append(f"Impact Assessment ({len(assessments)} detections)\n")

    for a in assessments:
        level_upper = a["impact_level"].upper()
        lines.append(
            f"  [{level_upper}] {a['detection_id']} ({a['detection_type']}) "
            f"— score {a['impact_score']:.1f}/10.0"
        )
        lines.append(f"    Severity: {a['severity']}")
        lines.append(f"    Agents affected: {len(a['agents_affected'])}")
        if a["agents_affected"]:
            lines.append(f"      {', '.join(a['agents_affected'][:5])}")
        lines.append(f"    Data stores accessed: {len(a['data_stores_accessed'])}")
        if a["data_stores_accessed"]:
            lines.append(f"      {', '.join(a['data_stores_accessed'][:5])}")
        lines.append(f"    API calls in window: {a['api_calls']}")
        lines.append(f"    Estimated data at risk: {a['estimated_data_bytes']} bytes")
        lines.append(f"    Events in window: {a['event_count']}")
        if a["citations"]:
            lines.append(f"    Evidence citations ({len(a['citations'])}):")
            for c in a["citations"][:5]:
                parts = []
                if c.get("file"):
                    parts.append(c["file"])
                if c.get("line"):
                    parts.append(f"line {c['line']}")
                if c.get("timestamp"):
                    parts.append(c["timestamp"])
                lines.append(f"      - {', '.join(parts)}")
        lines.append("")

    critical = sum(1 for a in assessments if a["impact_level"] == "critical")
    high = sum(1 for a in assessments if a["impact_level"] == "high")
    medium = sum(1 for a in assessments if a["impact_level"] == "medium")
    low = sum(1 for a in assessments if a["impact_level"] == "low")
    lines.append(f"Summary: {critical} critical, {high} high, {medium} medium, {low} low\n")

    return "\n".join(lines)
