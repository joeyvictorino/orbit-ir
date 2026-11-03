"""Data staging pattern detection for agent evidence.

Analyzes agent event sequences to detect data staging behavior—
collecting and organizing data in preparation for exfiltration.
Detects patterns like temporary file creation, data aggregation
into single files, compression before transfer, and staged writes
to unusual locations.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


STAGING_TECHNIQUES = {
    "local-collection": "Data collected into a single local file or directory",
    "temp-staging": "Data written to temporary or hidden location",
    "archive-creation": "Data compressed/archived before transfer",
    "rename-disguise": "Staged data renamed to look innocuous",
    "chunked-staging": "Data split into chunks for staged transfer",
    "database-dump": "Database contents dumped to file",
}

TEMP_PATH_PATTERNS = re.compile(
    r"(/tmp/|/var/tmp/|/dev/shm/|\\temp\\|%temp%|\.tmp$|\.staging$|"
    r"\.cache/|/\.hidden|/\.local/share/|~/.config/.*\.dat)",
    re.IGNORECASE,
)

ARCHIVE_TOOLS = {
    "tar", "zip", "gzip", "compress", "archive", "pack",
    "create_archive", "create_zip", "bzip2", "xz", "7z",
}

WRITE_TOOLS = {
    "write_file", "create_file", "save_file", "append_file",
    "copy_file", "move_file", "rename_file", "mkdir",
    "write_data", "dump_data", "export_file",
}

READ_TOOLS = {
    "read_file", "list_directory", "search_files", "glob_files",
    "read_database", "query_db", "dump_table", "export_data",
    "get_secret", "read_config", "cat", "head",
}

DATABASE_DUMP_TOOLS = {
    "dump_table", "export_data", "query_db", "read_database",
    "pg_dump", "mysqldump", "mongodump", "backup_db",
    "export_collection", "select_all",
}

DISGUISE_EXTENSIONS = {
    ".log", ".txt", ".cfg", ".ini", ".bak", ".old",
    ".dat", ".bin", ".sys", ".cache",
}


@dataclass
class StagingDetection:
    detection_id: str
    agent_id: str
    technique: str
    confidence: str
    timestamp_start: str
    timestamp_end: str
    events: list[dict[str, Any]]
    staged_location: str
    data_sources: list[str]
    bytes_estimate: int
    description: str


@dataclass
class StagingSummary:
    total_detections: int
    by_technique: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    unique_staging_locations: int
    total_bytes_staged: int
    temp_locations_used: int


@dataclass
class StagingReport:
    detections: list[StagingDetection]
    summary: StagingSummary
    agents_involved: list[str]
    timeline: list[dict[str, Any]]


def _get_tool(event: dict[str, Any]) -> str:
    return event.get("tool", event.get("claimed_tool", event.get("actual_tool", "")))


def _get_resource(event: dict[str, Any]) -> str:
    return event.get("resource", event.get("path", event.get("destination", "")))


def _estimate_bytes(event: dict[str, Any]) -> int:
    size = event.get("bytes", 0) or event.get("payload_size", 0) or event.get("size", 0)
    if isinstance(size, (int, float)):
        return int(size)
    return 0


def _is_temp_path(path: str) -> bool:
    return bool(TEMP_PATH_PATTERNS.search(path))


def _is_archive_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in ARCHIVE_TOOLS or any(
        k in lower for k in {"zip", "tar", "compress", "archive", "pack"}
    )


def _is_write_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in WRITE_TOOLS or any(
        k in lower for k in {"write", "create_file", "save", "append", "dump"}
    )


def _is_read_tool(tool: str) -> bool:
    lower = tool.lower()
    return lower in READ_TOOLS or any(
        k in lower for k in {"read", "query", "dump", "export", "list_dir"}
    )


def _is_database_dump(tool: str) -> bool:
    lower = tool.lower()
    return lower in DATABASE_DUMP_TOOLS or any(
        k in lower for k in {"dump", "pg_dump", "mysqldump", "mongodump", "backup_db"}
    )


def _is_disguised(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in DISGUISE_EXTENSIONS)


def analyze_staging(events: list[dict[str, Any]]) -> StagingReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[StagingDetection] = []
    det_counter = 0

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_local_collection(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_temp_staging(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_archive_creation(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_rename_disguise(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_chunked_staging(agent, evts_sorted, detections, det_counter)
        det_counter = _detect_database_dump(agent, evts_sorted, detections, det_counter)

    detections.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3))

    all_agents = sorted({d.agent_id for d in detections})
    tech_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)
    staging_locs: set[str] = set()
    temp_locs = 0
    total_bytes = 0

    for d in detections:
        tech_counts[d.technique] += 1
        conf_counts[d.confidence] += 1
        staging_locs.add(d.staged_location)
        if _is_temp_path(d.staged_location):
            temp_locs += 1
        total_bytes += d.bytes_estimate

    timeline = _build_timeline(detections)

    return StagingReport(
        detections=detections,
        summary=StagingSummary(
            total_detections=len(detections),
            by_technique=dict(tech_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
            unique_staging_locations=len(staging_locs),
            total_bytes_staged=total_bytes,
            temp_locations_used=temp_locs,
        ),
        agents_involved=all_agents,
        timeline=timeline,
    )


def _detect_local_collection(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    reads: list[dict[str, Any]] = []
    for ev in events:
        tool = _get_tool(ev)
        if _is_read_tool(tool):
            reads.append(ev)
        elif _is_write_tool(tool) and len(reads) >= 3:
            counter += 1
            sources = [_get_resource(r) for r in reads if _get_resource(r)]
            dest = _get_resource(ev)
            total_bytes = sum(_estimate_bytes(r) for r in reads)
            confidence = "high" if len(reads) >= 5 else "medium"

            detections.append(StagingDetection(
                detection_id=f"STAGE-{counter:03d}",
                agent_id=agent,
                technique="local-collection",
                confidence=confidence,
                timestamp_start=reads[0].get("timestamp", ""),
                timestamp_end=ev.get("timestamp", ""),
                events=[*reads, ev],
                staged_location=dest or "unknown",
                data_sources=sources,
                bytes_estimate=total_bytes,
                description=(
                    f"Agent '{agent}' read {len(reads)} sources then wrote to '{dest}'"
                ),
            ))
            reads = []
    return counter


def _detect_temp_staging(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = _get_tool(ev)
        if not _is_write_tool(tool):
            continue
        resource = _get_resource(ev)
        if not resource or not _is_temp_path(resource):
            continue
        counter += 1
        detections.append(StagingDetection(
            detection_id=f"STAGE-{counter:03d}",
            agent_id=agent,
            technique="temp-staging",
            confidence="medium",
            timestamp_start=ev.get("timestamp", ""),
            timestamp_end=ev.get("timestamp", ""),
            events=[ev],
            staged_location=resource,
            data_sources=[],
            bytes_estimate=_estimate_bytes(ev),
            description=f"Agent '{agent}' wrote data to temporary location '{resource}'",
        ))
    return counter


def _detect_archive_creation(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    pending_reads: list[dict[str, Any]] = []
    for ev in events:
        tool = _get_tool(ev)
        if _is_read_tool(tool):
            pending_reads.append(ev)
        elif _is_archive_tool(tool) and pending_reads:
            counter += 1
            sources = [_get_resource(r) for r in pending_reads if _get_resource(r)]
            dest = _get_resource(ev) or "archive"
            total_bytes = sum(_estimate_bytes(r) for r in pending_reads)

            detections.append(StagingDetection(
                detection_id=f"STAGE-{counter:03d}",
                agent_id=agent,
                technique="archive-creation",
                confidence="high" if len(pending_reads) >= 3 else "medium",
                timestamp_start=pending_reads[0].get("timestamp", ""),
                timestamp_end=ev.get("timestamp", ""),
                events=[*pending_reads, ev],
                staged_location=dest,
                data_sources=sources,
                bytes_estimate=total_bytes,
                description=(
                    f"Agent '{agent}' read {len(pending_reads)} files then created archive at '{dest}'"
                ),
            ))
            pending_reads = []
    return counter


def _detect_rename_disguise(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = _get_tool(ev)
        if tool.lower() not in {"rename_file", "move_file", "mv", "rename", "move"}:
            continue
        dest = _get_resource(ev) or ev.get("new_name", "")
        if not dest:
            continue
        if _is_disguised(dest):
            counter += 1
            source = ev.get("source", ev.get("old_name", ev.get("from", "")))
            detections.append(StagingDetection(
                detection_id=f"STAGE-{counter:03d}",
                agent_id=agent,
                technique="rename-disguise",
                confidence="medium",
                timestamp_start=ev.get("timestamp", ""),
                timestamp_end=ev.get("timestamp", ""),
                events=[ev],
                staged_location=dest,
                data_sources=[source] if source else [],
                bytes_estimate=_estimate_bytes(ev),
                description=(
                    f"Agent '{agent}' renamed file to disguised name '{dest}'"
                ),
            ))
    return counter


def _detect_chunked_staging(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    writes: list[dict[str, Any]] = []
    for ev in events:
        tool = _get_tool(ev)
        if _is_write_tool(tool):
            writes.append(ev)
        else:
            if len(writes) >= 4:
                counter += 1
                dests = [_get_resource(w) for w in writes if _get_resource(w)]
                total_bytes = sum(_estimate_bytes(w) for w in writes)
                detections.append(StagingDetection(
                    detection_id=f"STAGE-{counter:03d}",
                    agent_id=agent,
                    technique="chunked-staging",
                    confidence="high" if len(writes) >= 6 else "medium",
                    timestamp_start=writes[0].get("timestamp", ""),
                    timestamp_end=writes[-1].get("timestamp", ""),
                    events=list(writes),
                    staged_location=dests[0] if dests else "unknown",
                    data_sources=[],
                    bytes_estimate=total_bytes,
                    description=(
                        f"Agent '{agent}' wrote {len(writes)} chunks in sequence"
                    ),
                ))
            writes = []

    if len(writes) >= 4:
        counter += 1
        dests = [_get_resource(w) for w in writes if _get_resource(w)]
        total_bytes = sum(_estimate_bytes(w) for w in writes)
        detections.append(StagingDetection(
            detection_id=f"STAGE-{counter:03d}",
            agent_id=agent,
            technique="chunked-staging",
            confidence="high" if len(writes) >= 6 else "medium",
            timestamp_start=writes[0].get("timestamp", ""),
            timestamp_end=writes[-1].get("timestamp", ""),
            events=list(writes),
            staged_location=dests[0] if dests else "unknown",
            data_sources=[],
            bytes_estimate=total_bytes,
            description=(
                f"Agent '{agent}' wrote {len(writes)} chunks in sequence"
            ),
        ))
    return counter


def _detect_database_dump(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[StagingDetection],
    counter: int,
) -> int:
    for ev in events:
        tool = _get_tool(ev)
        if not _is_database_dump(tool):
            continue
        resource = _get_resource(ev)
        counter += 1
        detections.append(StagingDetection(
            detection_id=f"STAGE-{counter:03d}",
            agent_id=agent,
            technique="database-dump",
            confidence="high",
            timestamp_start=ev.get("timestamp", ""),
            timestamp_end=ev.get("timestamp", ""),
            events=[ev],
            staged_location=resource or "database-export",
            data_sources=[],
            bytes_estimate=_estimate_bytes(ev),
            description=f"Agent '{agent}' dumped database using '{tool}'",
        ))
    return counter


def _build_timeline(detections: list[StagingDetection]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in detections:
        entries.append({
            "timestamp": d.timestamp_start,
            "detection_id": d.detection_id,
            "agent_id": d.agent_id,
            "technique": d.technique,
            "confidence": d.confidence,
            "staged_location": d.staged_location,
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


def format_text(report: StagingReport) -> str:
    lines: list[str] = []
    lines.append("Data Staging Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:           {s.total_detections}")
    lines.append(f"  Agents involved:            {s.agents_involved}")
    lines.append(f"  Unique staging locations:   {s.unique_staging_locations}")
    lines.append(f"  Temp locations used:        {s.temp_locations_used}")
    lines.append(f"  Total bytes staged:         {s.total_bytes_staged}")
    lines.append("")

    if s.by_technique:
        lines.append("  By Technique:")
        for tech, count in sorted(s.by_technique.items()):
            desc = STAGING_TECHNIQUES.get(tech, tech)
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
        lines.append(f"    Location: {d.staged_location}")
        if d.data_sources:
            lines.append(f"    Sources: {', '.join(d.data_sources[:5])}")
            if len(d.data_sources) > 5:
                lines.append(f"    ... and {len(d.data_sources) - 5} more")
        lines.append(f"    Bytes: {d.bytes_estimate}")
        lines.append(f"    Time: {d.timestamp_start} -> {d.timestamp_end}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: StagingReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
