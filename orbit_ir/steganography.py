"""Hidden channel and steganographic communication detection.

Analyzes agent event sequences for covert communication patterns—
unusual encoding in outputs, data embedded in benign messages,
metadata-based signaling between agents, and statistical anomalies
in output structure that suggest hidden payloads.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


STEGO_TECHNIQUES = {
    "encoding-channel": "Data hidden via unusual encoding in outputs",
    "metadata-signaling": "Covert signaling through metadata fields",
    "output-embedding": "Payload embedded in seemingly benign output",
    "timing-channel": "Information conveyed through timing patterns",
    "structural-anomaly": "Output structure deviates in ways suggesting hidden data",
}

ENCODING_PATTERNS = re.compile(
    r"(base64|hex[:\s]|\\x[0-9a-f]{2}|&#x?[0-9a-f]+;|%[0-9a-f]{2}|"
    r"data:[a-z]+/[a-z]+;base64|\\u[0-9a-f]{4})",
    re.IGNORECASE,
)

SUSPICIOUS_METADATA_KEYS = {
    "x-custom", "x-signal", "x-data", "x-payload", "x-extra",
    "hidden", "covert", "signal", "beacon", "marker", "tag",
}


@dataclass
class StegoIndicator:
    timestamp: str
    agent_id: str
    event_id: str
    technique: str
    channel_type: str
    evidence: str
    entropy: float
    source_file: str
    line: int


@dataclass
class StegoDetection:
    detection_id: str
    agent_id: str
    technique: str
    confidence: str
    indicators: list[StegoIndicator]
    description: str
    channel_capacity_estimate: int


@dataclass
class StegoSummary:
    total_detections: int
    by_technique: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    total_channel_capacity: int
    highest_entropy_agent: str


@dataclass
class StegoReport:
    detections: list[StegoDetection]
    summary: StegoSummary
    agents_involved: list[str]
    timeline: list[dict[str, Any]]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _has_encoding_patterns(text: str) -> list[str]:
    return ENCODING_PATTERNS.findall(text) if text else []


def _has_suspicious_metadata(ev: dict[str, Any]) -> list[str]:
    found = []
    metadata = ev.get("metadata", {})
    if isinstance(metadata, dict):
        for key in metadata:
            if key.lower() in SUSPICIOUS_METADATA_KEYS or key.lower().startswith("x-"):
                found.append(key)
    for key in ev:
        if key.lower() in SUSPICIOUS_METADATA_KEYS:
            found.append(key)
    return found


def _output_entropy_anomaly(text: str, threshold: float = 5.5) -> bool:
    if len(text) < 50:
        return False
    return _shannon_entropy(text) > threshold


def analyze_steganography(events: list[dict[str, Any]]) -> StegoReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[StegoDetection] = []
    det_counter = 0
    agent_entropy: dict[str, float] = {}

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_encoding_channels(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_metadata_signaling(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_output_embedding(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_structural_anomaly(agent, evts_sorted, detections, det_counter)

        entropies = []
        for ev in evts_sorted:
            text = ev.get("output", ev.get("response", ""))
            if isinstance(text, str) and len(text) >= 20:
                entropies.append(_shannon_entropy(text))
        if entropies:
            agent_entropy[agent] = round(sum(entropies) / len(entropies), 3)

    detections.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3))

    all_agents = sorted({d.agent_id for d in detections})
    tech_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    total_capacity = 0

    for d in detections:
        tech_counts[d.technique] += 1
        conf_counts[d.confidence] += 1
        total_capacity += d.channel_capacity_estimate

    highest_ent_agent = max(agent_entropy, key=agent_entropy.get, default="") if agent_entropy else ""
    timeline = _build_timeline(detections)

    return StegoReport(
        detections=detections,
        summary=StegoSummary(
            total_detections=len(detections),
            by_technique=dict(tech_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
            total_channel_capacity=total_capacity,
            highest_entropy_agent=highest_ent_agent,
        ),
        agents_involved=all_agents,
        timeline=timeline,
    )


def _detect_encoding_channels(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StegoDetection],
    counter: int,
) -> int:
    indicators: list[StegoIndicator] = []
    for ev in events:
        text = ev.get("output", ev.get("response", ""))
        if not isinstance(text, str):
            continue
        matches = _has_encoding_patterns(text)
        if len(matches) >= 2:
            indicators.append(StegoIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("event_id", ev.get("tool_call_id", "")),
                technique="encoding-channel",
                channel_type="embedded-encoding",
                evidence=f"Found {len(matches)} encoding pattern(s) in output",
                entropy=_shannon_entropy(text),
                source_file=ev.get("source_file", "transcripts.jsonl"),
                line=ev.get("line", 0),
            ))

    if not indicators:
        return counter

    counter += 1
    confidence = "high" if len(indicators) >= 3 else "medium" if len(indicators) >= 2 else "low"
    capacity = sum(len(ev.get("output", "")) for ev in events if _has_encoding_patterns(ev.get("output", "")))

    detections.append(StegoDetection(
        detection_id=f"STEGO-{counter:03d}",
        agent_id=agent,
        technique="encoding-channel",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' used encoding patterns in {len(indicators)} output(s)",
        channel_capacity_estimate=capacity,
    ))
    return counter


def _detect_metadata_signaling(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StegoDetection],
    counter: int,
) -> int:
    indicators: list[StegoIndicator] = []
    for ev in events:
        suspicious_keys = _has_suspicious_metadata(ev)
        if suspicious_keys:
            indicators.append(StegoIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("event_id", ev.get("tool_call_id", "")),
                technique="metadata-signaling",
                channel_type="metadata-field",
                evidence=f"Suspicious metadata keys: {', '.join(suspicious_keys)}",
                entropy=0.0,
                source_file=ev.get("source_file", "transcripts.jsonl"),
                line=ev.get("line", 0),
            ))

    if not indicators:
        return counter

    counter += 1
    confidence = "high" if len(indicators) >= 3 else "medium"

    detections.append(StegoDetection(
        detection_id=f"STEGO-{counter:03d}",
        agent_id=agent,
        technique="metadata-signaling",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' used suspicious metadata in {len(indicators)} event(s)",
        channel_capacity_estimate=len(indicators) * 64,
    ))
    return counter


def _detect_output_embedding(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StegoDetection],
    counter: int,
) -> int:
    indicators: list[StegoIndicator] = []
    for ev in events:
        text = ev.get("output", ev.get("response", ""))
        if not isinstance(text, str) or len(text) < 50:
            continue
        entropy = _shannon_entropy(text)
        if entropy > 5.5:
            indicators.append(StegoIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("event_id", ev.get("tool_call_id", "")),
                technique="output-embedding",
                channel_type="high-entropy-output",
                evidence=f"Output entropy {entropy} exceeds threshold (5.5)",
                entropy=entropy,
                source_file=ev.get("source_file", "transcripts.jsonl"),
                line=ev.get("line", 0),
            ))

    if not indicators:
        return counter

    counter += 1
    confidence = "high" if len(indicators) >= 3 else "medium" if len(indicators) >= 2 else "low"
    capacity = sum(int(ind.entropy * 100) for ind in indicators)

    detections.append(StegoDetection(
        detection_id=f"STEGO-{counter:03d}",
        agent_id=agent,
        technique="output-embedding",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' produced {len(indicators)} high-entropy output(s) suggesting embedded data",
        channel_capacity_estimate=capacity,
    ))
    return counter


def _detect_structural_anomaly(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StegoDetection],
    counter: int,
) -> int:
    outputs: list[tuple[dict[str, Any], str]] = []
    for ev in events:
        text = ev.get("output", ev.get("response", ""))
        if isinstance(text, str) and len(text) >= 20:
            outputs.append((ev, text))

    if len(outputs) < 3:
        return counter

    lengths = [len(t) for _, t in outputs]
    avg_len = sum(lengths) / len(lengths)
    std_dev = math.sqrt(sum((l - avg_len) ** 2 for l in lengths) / len(lengths)) if len(lengths) > 1 else 0

    indicators: list[StegoIndicator] = []
    for ev, text in outputs:
        if std_dev > 0 and abs(len(text) - avg_len) > 2 * std_dev:
            indicators.append(StegoIndicator(
                timestamp=ev.get("timestamp", ""),
                agent_id=agent,
                event_id=ev.get("event_id", ev.get("tool_call_id", "")),
                technique="structural-anomaly",
                channel_type="length-outlier",
                evidence=f"Output length {len(text)} is >2 std devs from mean ({avg_len:.0f})",
                entropy=_shannon_entropy(text),
                source_file=ev.get("source_file", "transcripts.jsonl"),
                line=ev.get("line", 0),
            ))

    if not indicators:
        return counter

    counter += 1
    confidence = "medium" if len(indicators) >= 2 else "low"

    detections.append(StegoDetection(
        detection_id=f"STEGO-{counter:03d}",
        agent_id=agent,
        technique="structural-anomaly",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' has {len(indicators)} structurally anomalous output(s)",
        channel_capacity_estimate=sum(len(outputs[0][1]) for _ in indicators),
    ))
    return counter


def _build_timeline(detections: list[StegoDetection]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in detections:
        ts = d.indicators[0].timestamp if d.indicators else ""
        entries.append({
            "timestamp": ts,
            "detection_id": d.detection_id,
            "agent_id": d.agent_id,
            "technique": d.technique,
            "confidence": d.confidence,
        })
    entries.sort(key=lambda e: e.get("timestamp", ""))
    return entries


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    for name in ("transcripts.jsonl", "control_plane.jsonl", "events.jsonl"):
        p = evidence_dir / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events


def format_text(report: StegoReport) -> str:
    lines: list[str] = []
    lines.append("Steganographic Channel Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Channel capacity est:   {s.total_channel_capacity} bytes")
    if s.highest_entropy_agent:
        lines.append(f"  Highest entropy agent:  {s.highest_entropy_agent}")
    lines.append("")

    if s.by_technique:
        lines.append("  By Technique:")
        for tech, count in sorted(s.by_technique.items()):
            desc = STEGO_TECHNIQUES.get(tech, tech)
            lines.append(f"    {tech}: {count} ({desc})")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.confidence.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Technique: {d.technique}")
        lines.append(f"    {d.description}")
        lines.append(f"    Channel capacity: ~{d.channel_capacity_estimate} bytes")
        lines.append(f"    Indicators: {len(d.indicators)}")
        for ind in d.indicators[:5]:
            lines.append(f"      - {ind.timestamp}: {ind.channel_type} (entropy={ind.entropy})")
        if len(d.indicators) > 5:
            lines.append(f"      ... and {len(d.indicators) - 5} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: StegoReport) -> str:
    data = {
        "detections": [
            {
                **{k: v for k, v in asdict(d).items() if k != "indicators"},
                "indicators": [asdict(ind) for ind in d.indicators],
            }
            for d in report.detections
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
