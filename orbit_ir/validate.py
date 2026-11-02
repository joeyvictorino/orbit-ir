"""Evidence format validation for orbit-ir datasets.

Checks evidence files for structural correctness, field validation,
timestamp format, and cross-file referential integrity without running
the full analysis pipeline.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from .analyzer import EVIDENCE_FILES, SOURCE_FIELDS, EvidenceFormatError, _parse_timestamp


def validate_evidence(input_dir: Path) -> dict:
    """Validate evidence files and return a structured report.

    Returns a dict with:
      - files: per-file validation results
      - integrity: cross-file referential integrity checks
      - summary: overall counts
      - valid: True if no errors found
    """
    report: dict = {
        "files": {},
        "integrity": {},
        "summary": {"total_records": 0, "total_errors": 0, "total_warnings": 0},
        "valid": True,
    }

    records_by_file: dict[str, list[dict]] = {}

    for fname in EVIDENCE_FILES:
        path = input_dir / fname
        file_report = _validate_file(path)
        report["files"][fname] = file_report
        report["summary"]["total_records"] += file_report["records"]
        report["summary"]["total_errors"] += len(file_report["errors"])
        report["summary"]["total_warnings"] += len(file_report["warnings"])
        if file_report["errors"]:
            report["valid"] = False
        records_by_file[fname] = file_report.get("_rows", [])

    integrity = _check_integrity(records_by_file)
    report["integrity"] = integrity
    if integrity.get("errors"):
        report["valid"] = False
        report["summary"]["total_errors"] += len(integrity["errors"])
    report["summary"]["total_warnings"] += len(integrity.get("warnings", []))

    for fr in report["files"].values():
        fr.pop("_rows", None)

    return report


def _validate_file(path: Path) -> dict:
    result: dict = {
        "exists": path.exists(),
        "records": 0,
        "errors": [],
        "warnings": [],
        "_rows": [],
    }
    if not path.exists():
        result["errors"].append(f"{path.name}: file not found")
        return result

    if path.stat().st_size == 0:
        result["warnings"].append(f"{path.name}: file is empty")
        return result

    required = SOURCE_FIELDS.get(path.name, set())
    seen_ids: set[str] = set()
    timestamps: list[str] = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                result["errors"].append(f"{path.name}:{line_number}: invalid JSON: {exc.msg}")
                continue

            if not isinstance(row, dict):
                result["errors"].append(f"{path.name}:{line_number}: record must be an object")
                continue

            result["records"] += 1
            result["_rows"].append(row)

            missing = sorted(required - row.keys())
            if missing:
                result["errors"].append(
                    f"{path.name}:{line_number}: missing fields: {', '.join(missing)}"
                )

            ts = row.get("timestamp")
            if ts:
                try:
                    _parse_timestamp(ts, f"{path.name}:{line_number}")
                    timestamps.append(str(ts))
                except EvidenceFormatError as exc:
                    result["errors"].append(str(exc))

            id_field = _id_field_for(path.name)
            if id_field and id_field in row:
                val = row[id_field]
                if val in seen_ids:
                    result["warnings"].append(
                        f"{path.name}:{line_number}: duplicate {id_field}={val}"
                    )
                seen_ids.add(val)

    if timestamps and timestamps != sorted(timestamps):
        result["warnings"].append(f"{path.name}: timestamps are not monotonically ordered")

    return result


def _id_field_for(filename: str) -> str | None:
    return {
        "messages.jsonl": "event_id",
        "transcripts.jsonl": "tool_call_id",
        "control_plane.jsonl": "tool_call_id",
    }.get(filename)


def _check_integrity(records_by_file: dict[str, list[dict]]) -> dict:
    result: dict = {"errors": [], "warnings": [], "checks": []}

    transcripts = records_by_file.get("transcripts.jsonl", [])
    control = records_by_file.get("control_plane.jsonl", [])
    messages = records_by_file.get("messages.jsonl", [])

    transcript_agents = {r.get("agent_id") for r in transcripts if r.get("agent_id")}
    control_agents = {r.get("agent_id") for r in control if r.get("agent_id")}
    message_agents = {r.get("agent_id") for r in messages if r.get("agent_id")}
    all_agents = transcript_agents | control_agents | message_agents

    result["checks"].append({
        "name": "agent_id_coverage",
        "transcript_agents": len(transcript_agents),
        "control_agents": len(control_agents),
        "message_agents": len(message_agents),
        "total_unique": len(all_agents),
    })

    transcript_tool_calls = {r.get("tool_call_id") for r in transcripts if r.get("tool_call_id")}
    control_tool_calls = {r.get("tool_call_id") for r in control if r.get("tool_call_id")}

    only_transcript = transcript_tool_calls - control_tool_calls
    only_control = control_tool_calls - transcript_tool_calls
    matched = transcript_tool_calls & control_tool_calls

    result["checks"].append({
        "name": "tool_call_id_alignment",
        "matched": len(matched),
        "transcript_only": len(only_transcript),
        "control_only": len(only_control),
    })

    if not matched and transcript_tool_calls and control_tool_calls:
        result["errors"].append(
            "No tool_call_id matches between transcripts and control plane — "
            "files may be from different datasets"
        )

    transcript_traces = {r.get("trace_id") for r in transcripts if r.get("trace_id")}
    control_traces = {r.get("trace_id") for r in control if r.get("trace_id")}

    result["checks"].append({
        "name": "trace_id_alignment",
        "transcript_traces": len(transcript_traces),
        "control_traces": len(control_traces),
        "shared": len(transcript_traces & control_traces),
    })

    agents_in_messages_not_transcript = message_agents - transcript_agents - control_agents
    if agents_in_messages_not_transcript:
        result["warnings"].append(
            f"{len(agents_in_messages_not_transcript)} agent(s) in messages.jsonl "
            f"have no transcript or control-plane records"
        )

    return result
