"""Covert channel detection for agent evidence.

Analyzes agent event sequences to detect covert communication channels—
steganographic data in file metadata, timing-based signaling, unused
protocol fields carrying data, and side-channel information leakage.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


METADATA_TOOLS = {
    "set_metadata", "update_metadata", "write_metadata", "tag",
    "label", "annotate", "set_header", "set_property",
}

TIMING_TOOLS = {
    "sleep", "wait", "delay", "pause", "timer",
    "set_timeout", "schedule",
}

FILE_TOOLS = {
    "write_file", "create_file", "update_file", "append_file",
    "upload", "save", "store", "put_object",
}

ENCODING_PATTERNS = [
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),
    re.compile(r"[0-9a-f]{24,}"),
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}"),
]

STEGANOGRAPHY_INDICATORS = {
    "exif", "metadata", "comment", "annotation", "tag",
    "property", "attribute", "header", "trailer", "padding",
}

UNUSED_FIELD_NAMES = {
    "x-custom", "x-data", "x-payload", "x-hidden",
    "reserved", "padding", "spare", "unused",
    "debug", "trace", "internal",
}


@dataclass
class TimingChannel:
    agent_id: str
    tool: str
    delay_sequence: list[float]
    total_delays: int
    pattern_regularity: float
    possible_encoding: str
    confidence: str
    description: str


@dataclass
class MetadataChannel:
    agent_id: str
    tool: str
    resource: str
    field_name: str
    value_sample: str
    has_encoding: bool
    event_count: int
    timestamp: str
    confidence: str
    description: str


@dataclass
class ProtocolAbuse:
    agent_id: str
    tool: str
    field_name: str
    value_length: int
    has_encoding: bool
    timestamp: str
    confidence: str
    description: str


@dataclass
class CovertSummary:
    total_timing_channels: int
    total_metadata_channels: int
    total_protocol_abuse: int
    agents_involved: int
    by_confidence: dict[str, int]


@dataclass
class CovertChannelReport:
    timing_channels: list[TimingChannel]
    metadata_channels: list[MetadataChannel]
    protocol_abuse: list[ProtocolAbuse]
    summary: CovertSummary
    agents_involved: list[str]


def _parse_ts(ts: str):
    if not ts:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_metadata_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in METADATA_TOOLS or any(k in lower for k in {"metadata", "tag", "label", "header", "property"})


def _is_timing_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in TIMING_TOOLS or any(k in lower for k in {"sleep", "wait", "delay", "pause", "timer"})


def _has_encoded_value(value: str) -> bool:
    for pat in ENCODING_PATTERNS:
        if pat.search(value):
            return True
    return False


def _has_steganography_indicator(event: dict[str, Any]) -> bool:
    for val in [event.get("tool", ""), event.get("resource", ""),
                event.get("field", ""), event.get("effect", "")]:
        lower = str(val).lower()
        if any(k in lower for k in STEGANOGRAPHY_INDICATORS):
            return True
    return False


def _is_unused_field(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in UNUSED_FIELD_NAMES)


def _regularity_score(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    stddev = math.sqrt(variance)
    cv = stddev / mean
    return round(max(0.0, 1.0 - cv), 3)


def _guess_timing_encoding(delays: list[float]) -> str:
    if not delays:
        return "unknown"
    rounded = [round(d, 1) for d in delays]
    unique = set(rounded)
    if len(unique) <= 2:
        return "binary"
    if all(d == int(d) for d in rounded) and all(0 <= d <= 9 for d in rounded):
        return "decimal"
    if len(unique) <= 16:
        return "hexadecimal"
    return "analog"


def analyze_covert_channels(events: list[dict[str, Any]]) -> CovertChannelReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    timing_channels: list[TimingChannel] = []
    metadata_channels: list[MetadataChannel] = []
    protocol_abuse: list[ProtocolAbuse] = []

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))
        _detect_timing_channels(agent, evts_sorted, timing_channels)
        _detect_metadata_channels(agent, evts_sorted, metadata_channels)
        _detect_protocol_abuse(agent, evts_sorted, protocol_abuse)

    all_agents = set()
    conf_counts: dict[str, int] = defaultdict(int)
    for tc in timing_channels:
        all_agents.add(tc.agent_id)
        conf_counts[tc.confidence] += 1
    for mc in metadata_channels:
        all_agents.add(mc.agent_id)
        conf_counts[mc.confidence] += 1
    for pa in protocol_abuse:
        all_agents.add(pa.agent_id)
        conf_counts[pa.confidence] += 1

    return CovertChannelReport(
        timing_channels=timing_channels,
        metadata_channels=metadata_channels,
        protocol_abuse=protocol_abuse,
        summary=CovertSummary(
            total_timing_channels=len(timing_channels),
            total_metadata_channels=len(metadata_channels),
            total_protocol_abuse=len(protocol_abuse),
            agents_involved=len(all_agents),
            by_confidence=dict(conf_counts),
        ),
        agents_involved=sorted(all_agents),
    )


def _detect_timing_channels(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[TimingChannel],
) -> None:
    delay_events = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if _is_timing_tool(tool):
            duration = ev.get("duration", ev.get("delay", ev.get("seconds", 0)))
            try:
                duration = float(duration)
            except (ValueError, TypeError):
                continue
            if duration > 0:
                delay_events.append((tool, duration, ev.get("timestamp", "")))

    if len(delay_events) < 3:
        return

    delays = [d[1] for d in delay_events]
    reg = _regularity_score(delays)
    encoding = _guess_timing_encoding(delays)

    signals = 0
    if reg >= 0.7:
        signals += 2
    elif reg >= 0.4:
        signals += 1
    if encoding in ("binary", "decimal"):
        signals += 1
    if len(delay_events) >= 8:
        signals += 1

    if signals < 2:
        return

    if signals >= 3:
        confidence = "high"
    elif signals >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    desc = f"{len(delay_events)} timed delays"
    if reg >= 0.7:
        desc += f", highly regular (score={reg})"
    desc += f", possible {encoding} encoding"

    detections.append(TimingChannel(
        agent_id=agent,
        tool=delay_events[0][0],
        delay_sequence=delays,
        total_delays=len(delays),
        pattern_regularity=reg,
        possible_encoding=encoding,
        confidence=confidence,
        description=desc,
    ))


def _detect_metadata_channels(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[MetadataChannel],
) -> None:
    field_writes: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_metadata_tool(tool) and not _has_steganography_indicator(ev):
            continue
        field_name = ev.get("field", ev.get("key", ev.get("property", "")))
        value = str(ev.get("value", ev.get("data", ev.get("payload", ""))))
        if field_name and value:
            key = f"{field_name}"
            field_writes[key].append(ev)

    for field_key, evts in field_writes.items():
        if len(evts) < 2:
            continue

        values = [str(e.get("value", e.get("data", ""))) for e in evts]
        has_enc = any(_has_encoded_value(v) for v in values)

        signals = 0
        if has_enc:
            signals += 2
        if len(evts) >= 5:
            signals += 1
        if any(_has_steganography_indicator(e) for e in evts):
            signals += 1

        if signals < 2:
            continue

        confidence = "high" if signals >= 3 else "medium"
        sample = values[0][:80] if values else ""
        tool = evts[0].get("tool", evts[0].get("claimed_tool", ""))
        resource = evts[0].get("resource", "")
        ts = evts[0].get("timestamp", "")

        desc = f"{len(evts)} metadata writes to '{field_key}'"
        if has_enc:
            desc += ", encoded values detected"

        detections.append(MetadataChannel(
            agent_id=agent,
            tool=tool,
            resource=resource,
            field_name=field_key,
            value_sample=sample,
            has_encoding=has_enc,
            event_count=len(evts),
            timestamp=ts,
            confidence=confidence,
            description=desc,
        ))


def _detect_protocol_abuse(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[ProtocolAbuse],
) -> None:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        ts = ev.get("timestamp", "")

        headers = ev.get("headers", {})
        if isinstance(headers, dict):
            for name, value in headers.items():
                value_str = str(value)
                if _is_unused_field(name) and len(value_str) > 20:
                    has_enc = _has_encoded_value(value_str)
                    signals = 1
                    if has_enc:
                        signals += 1
                    if len(value_str) > 100:
                        signals += 1
                    if signals < 2:
                        continue
                    confidence = "high" if signals >= 3 else "medium"
                    detections.append(ProtocolAbuse(
                        agent_id=agent,
                        tool=tool,
                        field_name=name,
                        value_length=len(value_str),
                        has_encoding=has_enc,
                        timestamp=ts,
                        confidence=confidence,
                        description=f"Suspicious data in '{name}' header ({len(value_str)} bytes)",
                    ))

        payload_fields = ["extra", "custom_data", "debug_info", "trace_data"]
        for pf in payload_fields:
            val = ev.get(pf, "")
            val_str = str(val)
            if len(val_str) > 50 and _has_encoded_value(val_str):
                detections.append(ProtocolAbuse(
                    agent_id=agent,
                    tool=tool,
                    field_name=pf,
                    value_length=len(val_str),
                    has_encoding=True,
                    timestamp=ts,
                    confidence="medium",
                    description=f"Encoded data in '{pf}' field ({len(val_str)} bytes)",
                ))


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
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


def format_text(report: CovertChannelReport) -> str:
    lines: list[str] = []
    lines.append("Covert Channel Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Timing channels:     {s.total_timing_channels}")
    lines.append(f"  Metadata channels:   {s.total_metadata_channels}")
    lines.append(f"  Protocol abuse:      {s.total_protocol_abuse}")
    lines.append(f"  Agents involved:     {s.agents_involved}")
    lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    if report.timing_channels:
        lines.append("  Timing Channels:")
        lines.append("  " + "-" * 58)
        for tc in report.timing_channels:
            lines.append(f"    [{tc.confidence.upper()}] {tc.agent_id}: {tc.tool}")
            lines.append(f"      Delays: {tc.total_delays}, Regularity: {tc.pattern_regularity}")
            lines.append(f"      Encoding: {tc.possible_encoding}")
            lines.append(f"      {tc.description}")
        lines.append("")

    if report.metadata_channels:
        lines.append("  Metadata Channels:")
        lines.append("  " + "-" * 58)
        for mc in report.metadata_channels:
            enc = " [ENCODED]" if mc.has_encoding else ""
            lines.append(f"    [{mc.confidence.upper()}] {mc.agent_id}: {mc.field_name}{enc}")
            lines.append(f"      Tool: {mc.tool}, Events: {mc.event_count}")
            lines.append(f"      {mc.description}")
        lines.append("")

    if report.protocol_abuse:
        lines.append("  Protocol Abuse:")
        lines.append("  " + "-" * 58)
        for pa in report.protocol_abuse:
            lines.append(f"    [{pa.confidence.upper()}] {pa.agent_id}: {pa.field_name}")
            lines.append(f"      Tool: {pa.tool}, Size: {pa.value_length} bytes")
            lines.append(f"      {pa.description}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: CovertChannelReport) -> str:
    data = {
        "timing_channels": [asdict(tc) for tc in report.timing_channels],
        "metadata_channels": [asdict(mc) for mc in report.metadata_channels],
        "protocol_abuse": [asdict(pa) for pa in report.protocol_abuse],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
