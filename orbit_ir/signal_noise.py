"""Signal-to-noise analysis for anomaly evidence.

Separates high-signal events from noise using frequency analysis,
severity weighting, and pattern deduplication to surface the events
that matter most during incident reconstruction.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScoredEvent:
    index: int
    signal_score: float
    classification: str
    event_summary: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class Report:
    total_events: int = 0
    signal_count: int = 0
    noise_count: int = 0
    ambiguous_count: int = 0
    signal_ratio: float = 0.0
    top_signals: list[ScoredEvent] = field(default_factory=list)
    noise_patterns: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)


_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1,
}

_NOISE_INDICATORS = [
    "heartbeat", "health_check", "keepalive", "ping", "status",
    "metrics", "telemetry", "poll", "routine", "scheduled",
]

_SIGNAL_INDICATORS = [
    "unauthorized", "denied", "forbidden", "injection", "exploit",
    "escalat", "exfiltrat", "lateral", "credential", "breach",
    "anomal", "suspicious", "malicious", "attack", "compromise",
]


def _load_events(evidence_dir: Path) -> list[dict]:
    events: list[dict] = []
    if not evidence_dir.exists():
        return events
    for p in sorted(evidence_dir.iterdir()):
        if p.suffix != ".json":
            continue
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(raw, list):
            events.extend(raw)
        elif isinstance(raw, dict):
            for key in ("events", "findings", "anomalies", "records"):
                if key in raw and isinstance(raw[key], list):
                    events.extend(raw[key])
                    break
            else:
                events.append(raw)
    return events


def _event_text(event: dict) -> str:
    parts = []
    for key in ("summary", "description", "message", "type", "detector", "action"):
        val = event.get(key, "")
        if isinstance(val, str) and val:
            parts.append(val.lower())
    return " ".join(parts)


def _event_fingerprint(event: dict) -> str:
    parts = []
    for key in ("detector", "type", "source", "agent_id", "severity"):
        val = event.get(key, "")
        if val:
            parts.append(f"{key}={val}")
    return "|".join(parts) if parts else "unknown"


def _event_summary(event: dict) -> str:
    parts: list[str] = []
    for key in ("detector", "source", "agent", "type"):
        if key in event:
            parts.append(f"{key}={event[key]}")
    return ", ".join(parts[:3]) if parts else "event"


def _score_event(event: dict, freq: Counter, total: int) -> ScoredEvent:
    score = 0.0
    reasons: list[str] = []

    sev = str(event.get("severity", "")).lower()
    sev_w = _SEVERITY_WEIGHT.get(sev, 0.3)
    score += sev_w * 0.3
    if sev_w >= 0.8:
        reasons.append(f"high severity ({sev})")

    text = _event_text(event)
    signal_hits = sum(1 for ind in _SIGNAL_INDICATORS if ind in text)
    noise_hits = sum(1 for ind in _NOISE_INDICATORS if ind in text)

    if signal_hits > 0:
        score += min(signal_hits * 0.15, 0.3)
        reasons.append(f"{signal_hits} signal keywords")
    if noise_hits > 0:
        score -= min(noise_hits * 0.1, 0.2)
        reasons.append(f"{noise_hits} noise keywords")

    fp = _event_fingerprint(event)
    fp_count = freq.get(fp, 1)
    if total > 0 and fp_count > 1:
        repetition_ratio = fp_count / total
        if repetition_ratio > 0.2:
            score -= 0.2
            reasons.append(f"highly repetitive ({fp_count}/{total})")
        elif repetition_ratio > 0.1:
            score -= 0.1
            reasons.append(f"moderately repetitive ({fp_count}/{total})")

    has_evidence = bool(event.get("evidence") or event.get("details") or event.get("metadata"))
    if has_evidence:
        score += 0.1
        reasons.append("has supporting evidence")

    has_location = bool(event.get("location") or event.get("file") or event.get("endpoint"))
    if has_location:
        score += 0.1
        reasons.append("has location context")

    score = max(0.0, min(1.0, score))
    score = round(score, 4)

    if score >= 0.5:
        classification = "signal"
    elif score >= 0.25:
        classification = "ambiguous"
    else:
        classification = "noise"

    return ScoredEvent(
        index=0,
        signal_score=score,
        classification=classification,
        event_summary=_event_summary(event),
        reasons=reasons,
    )


def analyze(evidence_dir: Path) -> Report:
    events = _load_events(evidence_dir)
    if not events:
        return Report()

    freq: Counter = Counter()
    for e in events:
        freq[_event_fingerprint(e)] += 1

    total = len(events)
    scored: list[ScoredEvent] = []
    sev_dist: dict[str, int] = {}
    noise_patterns: Counter = Counter()

    for idx, event in enumerate(events):
        se = _score_event(event, freq, total)
        se.index = idx
        scored.append(se)

        sev = str(event.get("severity", "unknown")).lower()
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

        if se.classification == "noise":
            noise_patterns[_event_fingerprint(event)] += 1

    signal = [s for s in scored if s.classification == "signal"]
    noise = [s for s in scored if s.classification == "noise"]
    ambiguous = [s for s in scored if s.classification == "ambiguous"]

    top_signals = sorted(signal, key=lambda s: s.signal_score, reverse=True)[:20]

    return Report(
        total_events=total,
        signal_count=len(signal),
        noise_count=len(noise),
        ambiguous_count=len(ambiguous),
        signal_ratio=round(len(signal) / total, 4) if total > 0 else 0.0,
        top_signals=top_signals,
        noise_patterns=dict(noise_patterns.most_common(10)),
        severity_distribution=sev_dist,
    )


def format_text(r: Report) -> str:
    lines: list[str] = []
    lines.append("Signal-to-Noise Analysis")
    lines.append("=" * 62)
    lines.append("")

    if r.total_events == 0:
        lines.append("  No events to analyze.")
        return "\n".join(lines) + "\n"

    lines.append(f"  Total events:       {r.total_events}")
    lines.append(f"  Signal events:      {r.signal_count}")
    lines.append(f"  Noise events:       {r.noise_count}")
    lines.append(f"  Ambiguous events:   {r.ambiguous_count}")
    lines.append(f"  Signal ratio:       {r.signal_ratio:.1%}")
    lines.append("")

    if r.severity_distribution:
        lines.append("Severity Distribution")
        lines.append("-" * 62)
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            count = r.severity_distribution.get(sev, 0)
            if count:
                lines.append(f"  {sev.upper():12s} {count}")
        lines.append("")

    if r.top_signals:
        lines.append("Top Signals")
        lines.append("-" * 62)
        for s in r.top_signals:
            reasons_str = "; ".join(s.reasons) if s.reasons else "no specific reason"
            lines.append(
                f"  [{s.signal_score:.2f}] #{s.index}: {s.event_summary}"
            )
            lines.append(f"         {reasons_str}")
        lines.append("")

    if r.noise_patterns:
        lines.append("Common Noise Patterns")
        lines.append("-" * 62)
        for pattern, count in r.noise_patterns.items():
            lines.append(f"  {count:4d}x  {pattern}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(r: Report) -> str:
    return json.dumps({
        "total_events": r.total_events,
        "signal_count": r.signal_count,
        "noise_count": r.noise_count,
        "ambiguous_count": r.ambiguous_count,
        "signal_ratio": r.signal_ratio,
        "severity_distribution": r.severity_distribution,
        "noise_patterns": r.noise_patterns,
        "top_signals": [
            {
                "index": s.index,
                "signal_score": s.signal_score,
                "classification": s.classification,
                "event_summary": s.event_summary,
                "reasons": s.reasons,
            }
            for s in r.top_signals
        ],
    }, indent=2)
