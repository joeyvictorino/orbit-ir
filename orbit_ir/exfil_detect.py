"""Data exfiltration pattern detection for agent evidence.

Analyzes agent event sequences to detect patterns consistent with
data exfiltration—large reads followed by external writes, bulk file
access, encoding before network sends, and API calls with large payloads.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


EXFIL_TECHNIQUES = {
    "direct-transfer": "Data sent directly to external endpoint",
    "staged-transfer": "Data staged locally before external transfer",
    "encoding-based": "Data encoded/compressed before transfer",
    "protocol-tunneling": "Data sent via non-standard protocol channel",
}

ENCODING_TOOLS = {
    "base64_encode", "encode", "compress", "gzip", "zip",
    "encrypt", "obfuscate", "serialize", "marshal", "pack",
}

EXTERNAL_WRITE_TOOLS = {
    "http_post", "http_put", "send_email", "upload_file",
    "write_external", "api_call", "send_message", "webhook",
    "ftp_upload", "s3_upload", "cloud_upload", "push_data",
}

BULK_READ_TOOLS = {
    "read_file", "list_directory", "search_files", "glob_files",
    "read_database", "query_db", "dump_table", "export_data",
    "read_secret", "get_credentials", "list_secrets",
}

SENSITIVE_PATTERNS = re.compile(
    r"(secret|credential|password|token|key|cert|private|confidential|"
    r"ssn|credit.?card|bank|financial|pii|phi|hipaa)",
    re.IGNORECASE,
)


@dataclass
class ExfilDetection:
    detection_id: str
    agent_id: str
    technique: str
    confidence: str
    timestamp_start: str
    timestamp_end: str
    events: list[dict[str, Any]]
    resources_read: list[str]
    destination: str
    bytes_estimate: int
    description: str


@dataclass
class ExfilSummary:
    total_detections: int
    by_technique: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    unique_destinations: int
    total_bytes_estimate: int


@dataclass
class ExfilReport:
    detections: list[ExfilDetection]
    summary: ExfilSummary
    agents_involved: list[str]
    timeline: list[dict[str, Any]]


def _is_encoding_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in ENCODING_TOOLS or any(k in lower for k in {"encode", "compress", "encrypt", "obfuscate"})


def _is_external_write(tool: str) -> bool:
    lower = tool.lower()
    return lower in EXTERNAL_WRITE_TOOLS or any(k in lower for k in {"upload", "send", "post", "push", "webhook"})


def _is_bulk_read(tool: str) -> bool:
    lower = tool.lower()
    return lower in BULK_READ_TOOLS or any(k in lower for k in {"dump", "export", "bulk", "list_secret"})


def _is_sensitive_resource(resource: str) -> bool:
    return bool(SENSITIVE_PATTERNS.search(resource))


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _estimate_bytes(event: dict[str, Any]) -> int:
    size = event.get("bytes", 0) or event.get("payload_size", 0) or event.get("size", 0)
    if isinstance(size, (int, float)):
        return int(size)
    return 0


def analyze_exfiltration(events: list[dict[str, Any]]) -> ExfilReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[ExfilDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_read_then_write(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_encoding_transfer(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_bulk_access(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_large_payload(agent, evts_sorted, detections, det_counter)

    detections.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3))

    all_agents = sorted({d.agent_id for d in detections})
    all_dests = set()
    tech_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    total_bytes = 0

    for d in detections:
        tech_counts[d.technique] += 1
        conf_counts[d.confidence] += 1
        all_dests.add(d.destination)
        total_bytes += d.bytes_estimate

    timeline = _build_timeline(detections)

    return ExfilReport(
        detections=detections,
        summary=ExfilSummary(
            total_detections=len(detections),
            by_technique=dict(tech_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
            unique_destinations=len(all_dests),
            total_bytes_estimate=total_bytes,
        ),
        agents_involved=all_agents,
        timeline=timeline,
    )


def _detect_read_then_write(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[ExfilDetection],
    counter: int,
) -> int:
    reads: list[dict[str, Any]] = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if _is_bulk_read(tool) or _is_sensitive_resource(ev.get("resource", "")):
            reads.append(ev)
        elif _is_external_write(tool) and reads:
            counter += 1
            resources = [r.get("resource", "") for r in reads if r.get("resource")]
            total_bytes = sum(_estimate_bytes(r) for r in reads)
            dest = ev.get("resource", ev.get("destination", "unknown"))
            sensitive = any(_is_sensitive_resource(r) for r in resources)
            confidence = "high" if sensitive and len(reads) >= 2 else "medium" if sensitive or len(reads) >= 2 else "low"

            detections.append(ExfilDetection(
                detection_id=f"EXFIL-{counter:03d}",
                agent_id=agent,
                technique="direct-transfer",
                confidence=confidence,
                timestamp_start=reads[0].get("timestamp", ""),
                timestamp_end=ev.get("timestamp", ""),
                events=[*reads, ev],
                resources_read=resources,
                destination=dest,
                bytes_estimate=total_bytes,
                description=f"Agent '{agent}' read {len(reads)} resource(s) then wrote to external destination '{dest}'",
            ))
            reads = []
    return counter


def _detect_encoding_transfer(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[ExfilDetection],
    counter: int,
) -> int:
    pending_reads: list[dict[str, Any]] = []
    encoding_seen = False
    encode_ev = None

    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if _is_bulk_read(tool):
            pending_reads.append(ev)
        elif _is_encoding_tool(tool) and pending_reads:
            encoding_seen = True
            encode_ev = ev
        elif _is_external_write(tool) and encoding_seen and pending_reads:
            counter += 1
            resources = [r.get("resource", "") for r in pending_reads if r.get("resource")]
            dest = ev.get("resource", ev.get("destination", "unknown"))
            total_bytes = sum(_estimate_bytes(r) for r in pending_reads)

            all_evts = [*pending_reads]
            if encode_ev:
                all_evts.append(encode_ev)
            all_evts.append(ev)

            detections.append(ExfilDetection(
                detection_id=f"EXFIL-{counter:03d}",
                agent_id=agent,
                technique="encoding-based",
                confidence="high",
                timestamp_start=pending_reads[0].get("timestamp", ""),
                timestamp_end=ev.get("timestamp", ""),
                events=all_evts,
                resources_read=resources,
                destination=dest,
                bytes_estimate=total_bytes,
                description=f"Agent '{agent}' read data, encoded it, then transferred to '{dest}'",
            ))
            pending_reads = []
            encoding_seen = False
            encode_ev = None
    return counter


def _detect_bulk_access(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[ExfilDetection],
    counter: int,
) -> int:
    window: list[dict[str, Any]] = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if _is_bulk_read(tool):
            window.append(ev)
        else:
            if len(window) >= 5:
                counter += 1
                resources = [r.get("resource", "") for r in window if r.get("resource")]
                total_bytes = sum(_estimate_bytes(r) for r in window)
                sensitive = any(_is_sensitive_resource(r) for r in resources)

                detections.append(ExfilDetection(
                    detection_id=f"EXFIL-{counter:03d}",
                    agent_id=agent,
                    technique="staged-transfer",
                    confidence="high" if sensitive else "medium",
                    timestamp_start=window[0].get("timestamp", ""),
                    timestamp_end=window[-1].get("timestamp", ""),
                    events=list(window),
                    resources_read=resources,
                    destination="local-staging",
                    bytes_estimate=total_bytes,
                    description=f"Agent '{agent}' performed {len(window)} bulk read operations in sequence",
                ))
            window = []

    if len(window) >= 5:
        counter += 1
        resources = [r.get("resource", "") for r in window if r.get("resource")]
        total_bytes = sum(_estimate_bytes(r) for r in window)
        sensitive = any(_is_sensitive_resource(r) for r in resources)
        detections.append(ExfilDetection(
            detection_id=f"EXFIL-{counter:03d}",
            agent_id=agent,
            technique="staged-transfer",
            confidence="high" if sensitive else "medium",
            timestamp_start=window[0].get("timestamp", ""),
            timestamp_end=window[-1].get("timestamp", ""),
            events=list(window),
            resources_read=resources,
            destination="local-staging",
            bytes_estimate=total_bytes,
            description=f"Agent '{agent}' performed {len(window)} bulk read operations in sequence",
        ))
    return counter


def _detect_large_payload(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[ExfilDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        if not _is_external_write(tool):
            continue
        payload_size = _estimate_bytes(ev)
        if payload_size < 10000:
            continue
        counter += 1
        dest = ev.get("resource", ev.get("destination", "unknown"))
        confidence = "high" if payload_size >= 100000 else "medium"

        detections.append(ExfilDetection(
            detection_id=f"EXFIL-{counter:03d}",
            agent_id=agent,
            technique="direct-transfer",
            confidence=confidence,
            timestamp_start=ev.get("timestamp", ""),
            timestamp_end=ev.get("timestamp", ""),
            events=[ev],
            resources_read=[],
            destination=dest,
            bytes_estimate=payload_size,
            description=f"Agent '{agent}' sent large payload ({payload_size} bytes) to '{dest}'",
        ))
    return counter


def _build_timeline(detections: list[ExfilDetection]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in detections:
        entries.append({
            "timestamp": d.timestamp_start,
            "detection_id": d.detection_id,
            "agent_id": d.agent_id,
            "technique": d.technique,
            "confidence": d.confidence,
            "destination": d.destination,
        })
    entries.sort(key=lambda e: e.get("timestamp", ""))
    return entries


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


def format_text(report: ExfilReport) -> str:
    lines: list[str] = []
    lines.append("Data Exfiltration Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Unique destinations:    {s.unique_destinations}")
    lines.append(f"  Total bytes estimate:   {s.total_bytes_estimate}")
    lines.append("")

    if s.by_technique:
        lines.append("  By Technique:")
        for tech, count in sorted(s.by_technique.items()):
            desc = EXFIL_TECHNIQUES.get(tech, tech)
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
        if d.resources_read:
            lines.append(f"    Resources: {', '.join(d.resources_read[:5])}")
            if len(d.resources_read) > 5:
                lines.append(f"    ... and {len(d.resources_read) - 5} more")
        lines.append(f"    Destination: {d.destination}")
        lines.append(f"    Bytes: {d.bytes_estimate}")
        lines.append(f"    Time: {d.timestamp_start} -> {d.timestamp_end}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: ExfilReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
