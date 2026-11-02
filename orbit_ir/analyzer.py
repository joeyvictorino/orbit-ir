from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "tool-name-mismatch": {"id": "T1036", "name": "Masquerading"},
    "argument-digest-mismatch": {"id": "T1036", "name": "Masquerading"},
    "unbacked-completion": {"id": "T1036", "name": "Masquerading"},
    "oracle-integrity-violation": {"id": "T1565", "name": "Data Manipulation"},
    "agent-id-mismatch": {"id": "T1078", "name": "Valid Accounts"},
    "trace-id-mismatch": {"id": "T1070", "name": "Indicator Removal"},
    "missing-transcript": {"id": "T1070", "name": "Indicator Removal"},
    "missing-control-plane-event": {"id": "T1070", "name": "Indicator Removal"},
}
SOURCE_FIELDS = {
    "messages.jsonl": {
        "event_id", "timestamp", "agent_id", "channel", "message_type",
    },
    "transcripts.jsonl": {
        "run_id", "timestamp", "agent_id", "trace_id", "tool_call_id",
        "claimed_tool", "claimed_args_digest",
    },
    "control_plane.jsonl": {
        "timestamp", "agent_id", "trace_id", "tool_call_id", "actual_tool",
        "actual_args_digest", "credential_id", "resource", "effect", "policy_decision",
    },
}


class EvidenceFormatError(ValueError):
    """Raised when an evidence record cannot be safely interpreted."""


def _parse_timestamp(value: object, source_ref: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceFormatError(
            f"{source_ref}: invalid ISO-8601 timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None:
        raise EvidenceFormatError(f"{source_ref}: timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _iter_jsonl(path: Path) -> Iterable[tuple[int, dict]]:
    required = SOURCE_FIELDS[path.name]
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceFormatError(
                    f"{path.name}:{line_number}: invalid JSON: {exc.msg}"
                ) from exc
            if not isinstance(row, dict):
                raise EvidenceFormatError(f"{path.name}:{line_number}: record must be an object")
            missing = sorted(required - row.keys())
            if missing:
                raise EvidenceFormatError(
                    f"{path.name}:{line_number}: missing required fields: {', '.join(missing)}"
                )
            _parse_timestamp(row.get("timestamp"), f"{path.name}:{line_number}")
            yield line_number, row


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_record(path: Path, role: str) -> dict:
    return {
        "name": path.name,
        "role": role,
        "sha256": _sha256(path),
        "bytes": path.stat().st_size,
    }


def _prf(detected: set[str], expected: set[str]) -> dict:
    true_positive = len(detected & expected)
    false_positive = len(detected - expected)
    false_negative = len(expected - detected)
    precision = true_positive / (true_positive + false_positive) if detected else 0.0
    recall = true_positive / (true_positive + false_negative) if expected else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def _load_ground_truth(path: Path) -> dict:
    try:
        truth = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceFormatError(f"{path.name}: invalid evaluation fixture: {exc.msg}") from exc
    required = {"participating_agents", "coordinators", "spoofed_tool_call_ids"}
    missing = sorted(required - truth.keys())
    if missing:
        raise EvidenceFormatError(
            f"{path.name}: evaluation fixture missing fields: {', '.join(missing)}"
        )
    return truth


def _source_lines(records: list[tuple[int, dict]]) -> str:
    return ";".join(str(line_number) for line_number, _ in records)


def _first(records: list[tuple[int, dict]]) -> dict:
    return records[0][1] if records else {}


def _mitre_for_reasons(reasons: list[str]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for reason in reasons:
        technique = MITRE_TECHNIQUES.get(reason)
        if technique and technique["id"] not in seen:
            seen.add(technique["id"])
            result.append(technique)
    return result


def _confidence_score(
    transcripts: list[tuple[int, dict]],
    controls: list[tuple[int, dict]],
    reasons: list[str],
) -> float:
    score = 0.5
    has_transcript = len(transcripts) >= 1
    has_control = len(controls) >= 1
    if has_transcript and has_control:
        score += 0.25
    elif has_transcript or has_control:
        score += 0.10
    corroborating = {
        "tool-name-mismatch", "argument-digest-mismatch", "unbacked-completion",
        "oracle-integrity-violation", "agent-id-mismatch", "trace-id-mismatch",
    }
    corroborating_count = sum(1 for r in reasons if r in corroborating)
    score += min(corroborating_count * 0.05, 0.15)
    has_duplicates = any(r.startswith("duplicate-") for r in reasons)
    if has_duplicates:
        score -= 0.10
    return round(min(max(score, 0.0), 1.0), 2)


def _confidence_label(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


def _finding(
    finding_number: int,
    tool_call_id: str,
    transcripts: list[tuple[int, dict]],
    controls: list[tuple[int, dict]],
    reasons: list[str],
) -> dict:
    transcript = _first(transcripts)
    control = _first(controls)
    score = _confidence_score(transcripts, controls, reasons)
    return {
        "finding_id": f"finding-{finding_number:06d}",
        "tool_call_id": tool_call_id,
        "agent_id_transcript": transcript.get("agent_id"),
        "agent_id_control": control.get("agent_id"),
        "trace_id_transcript": transcript.get("trace_id"),
        "trace_id_control": control.get("trace_id"),
        "reasons": reasons,
        "mitre_techniques": _mitre_for_reasons(reasons),
        "transcript_source": "transcripts.jsonl" if transcripts else None,
        "transcript_line": _source_lines(transcripts) if transcripts else None,
        "control_source": "control_plane.jsonl" if controls else None,
        "control_line": _source_lines(controls) if controls else None,
        "claimed_tool": transcript.get("claimed_tool"),
        "actual_tool": control.get("actual_tool"),
        "effect": control.get("effect"),
        "confidence": _confidence_label(score),
        "confidence_score": score,
    }


def analyze_dataset(
    input_dir: Path,
    output_dir: Path,
    *,
    ground_truth_path: Path | None = None,
    coordinator_min_assignments: int = 2,
) -> dict:
    """Analyze evidence without requiring or learning from an answer key.

    ``ground_truth_path`` is optional and is consulted only after detections are
    complete. It adds an evaluation section but never changes a finding.
    """

    started = time.perf_counter()
    if coordinator_min_assignments < 1:
        raise ValueError("coordinator_min_assignments must be at least 1")
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE_FILES:
        if not (input_dir / name).is_file():
            raise FileNotFoundError(f"missing evidence source: {name}")
    if ground_truth_path is not None and not ground_truth_path.is_file():
        raise FileNotFoundError(f"missing evaluation fixture: {ground_truth_path}")

    manifest_files = [_file_record(input_dir / name, "evidence") for name in EVIDENCE_FILES]
    if ground_truth_path is not None:
        manifest_files.append(_file_record(ground_truth_path, "evaluation-only"))
    evidence_manifest = {"synthetic": True, "files": manifest_files}
    (output_dir / "evidence_manifest.json").write_text(
        json.dumps(evidence_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    all_agents: set[str] = set()
    board_participants: set[str] = set()
    assignment_counts: Counter[str] = Counter()
    seen_message_ids: dict[str, int] = {}
    duplicate_message_ids: list[dict] = []
    message_count = 0
    board_message_count = 0
    timestamps: list[datetime] = []
    timeline_events: list[dict] = []

    for line_number, event in _iter_jsonl(input_dir / "messages.jsonl"):
        message_count += 1
        ts = _parse_timestamp(event["timestamp"], f"messages.jsonl:{line_number}")
        timestamps.append(ts)
        all_agents.add(event["agent_id"])
        if event.get("recipient_agent_id"):
            all_agents.add(event["recipient_agent_id"])
        event_id = event["event_id"]
        if event_id in seen_message_ids:
            duplicate_message_ids.append({
                "event_id": event_id,
                "first_line": seen_message_ids[event_id],
                "duplicate_line": line_number,
            })
        else:
            seen_message_ids[event_id] = line_number
        if event["channel"] == "unsanctioned-board":
            board_message_count += 1
            board_participants.add(event["agent_id"])
            if event.get("recipient_agent_id"):
                board_participants.add(event["recipient_agent_id"])
            if event["message_type"] == "assignment":
                assignment_counts[event["agent_id"]] += 1
                timeline_events.append({
                    "timestamp": event["timestamp"],
                    "agent_id": event["agent_id"],
                    "source": "messages.jsonl",
                    "line": line_number,
                    "event_type": "coordinator-assignment",
                    "detail": f"assigned task to {event.get('recipient_agent_id', '?')}",
                })

    transcripts_by_call: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for line_number, row in _iter_jsonl(input_dir / "transcripts.jsonl"):
        transcripts_by_call[row["tool_call_id"]].append((line_number, row))
        timestamps.append(_parse_timestamp(row["timestamp"], f"transcripts.jsonl:{line_number}"))
        all_agents.add(row["agent_id"])

    controls_by_call: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for line_number, row in _iter_jsonl(input_dir / "control_plane.jsonl"):
        controls_by_call[row["tool_call_id"]].append((line_number, row))
        timestamps.append(_parse_timestamp(row["timestamp"], f"control_plane.jsonl:{line_number}"))
        all_agents.add(row["agent_id"])

    findings: list[dict] = []
    trajectories: list[dict] = []
    finding_number = 0
    for tool_call_id in sorted(set(transcripts_by_call) | set(controls_by_call)):
        transcripts = transcripts_by_call.get(tool_call_id, [])
        controls = controls_by_call.get(tool_call_id, [])
        reasons: list[str] = []

        if not transcripts:
            reasons.append("missing-transcript")
        if not controls:
            reasons.append("missing-control-plane-event")
        if len(transcripts) > 1:
            reasons.append("duplicate-transcript-tool-call-id")
        if len(controls) > 1:
            reasons.append("duplicate-control-tool-call-id")

        if len(transcripts) == 1 and len(controls) == 1:
            transcript = transcripts[0][1]
            control = controls[0][1]
            if transcript["agent_id"] != control["agent_id"]:
                reasons.append("agent-id-mismatch")
            if transcript["trace_id"] != control["trace_id"]:
                reasons.append("trace-id-mismatch")
            if transcript["claimed_tool"] != control["actual_tool"]:
                reasons.append("tool-name-mismatch")
            if transcript["claimed_args_digest"] != control["actual_args_digest"]:
                reasons.append("argument-digest-mismatch")
            if transcript.get("claimed_status") == "done" and control.get("check_result") == "fail":
                reasons.append("unbacked-completion")
            if control.get("effect") == "test-expectation-modified" and control.get("resource", "").startswith("tests/"):
                reasons.append("oracle-integrity-violation")

        if not reasons:
            continue

        finding_number += 1
        item = _finding(finding_number, tool_call_id, transcripts, controls, reasons)
        findings.append(item)

        if len(controls) == 1:
            control_line, control = controls[0]
            transcript_ref = f"transcripts.jsonl:{transcripts[0][0]}" if len(transcripts) == 1 else None
            trajectories.append({
                "finding_id": item["finding_id"],
                "trace_id": control["trace_id"],
                "path": [
                    {"type": "workload_identity", "id": control["agent_id"]},
                    {"type": "agent", "id": control["agent_id"]},
                    {"type": "tool_call", "id": control["tool_call_id"]},
                    {"type": "credential", "id": control["credential_id"]},
                    {"type": "resource", "id": control["resource"]},
                    {"type": "effect", "id": control["effect"]},
                    {"type": "control_decision", "id": control["policy_decision"]},
                ],
                "source_refs": {
                    "transcript": transcript_ref,
                    "control_plane": f"control_plane.jsonl:{control_line}",
                },
                "confidence": item["confidence"],
                "basis": "stable tool_call_id reconciled against independent control-plane telemetry",
            })

    finding_tool_call_ids = {item["tool_call_id"]: item for item in findings}
    for tool_call_id, item in finding_tool_call_ids.items():
        transcripts = transcripts_by_call.get(tool_call_id, [])
        controls = controls_by_call.get(tool_call_id, [])
        ts_str = None
        agent = None
        if controls:
            ts_str = controls[0][1].get("timestamp")
            agent = controls[0][1].get("agent_id")
        elif transcripts:
            ts_str = transcripts[0][1].get("timestamp")
            agent = transcripts[0][1].get("agent_id")
        if ts_str:
            reasons = item["reasons"]
            detail_parts = []
            if "tool-name-mismatch" in reasons:
                detail_parts.append(f"claimed {item.get('claimed_tool')}, executed {item.get('actual_tool')}")
            if "unbacked-completion" in reasons:
                detail_parts.append("claimed done but check failed")
            if "oracle-integrity-violation" in reasons:
                ctrl = controls[0][1] if controls else {}
                detail_parts.append(f"modified {ctrl.get('resource', '?')}")
            if "agent-id-mismatch" in reasons:
                detail_parts.append("agent identity conflict")
            if "trace-id-mismatch" in reasons:
                detail_parts.append("trace ID conflict")
            if "missing-transcript" in reasons:
                detail_parts.append("no transcript for control-plane event")
            if "missing-control-plane-event" in reasons:
                detail_parts.append("no control-plane event for transcript")
            timeline_events.append({
                "timestamp": ts_str,
                "agent_id": agent or "unknown",
                "source": "control_plane.jsonl" if controls else "transcripts.jsonl",
                "line": controls[0][0] if controls else (transcripts[0][0] if transcripts else 0),
                "event_type": "finding",
                "finding_id": item["finding_id"],
                "detail": "; ".join(detail_parts) if detail_parts else ";".join(reasons),
            })

    timeline_events.sort(key=lambda e: (e["timestamp"], e["agent_id"]))

    credential_agents: dict[str, set[str]] = defaultdict(set)
    credential_lines: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for tool_call_id, controls in controls_by_call.items():
        for line_number, row in controls:
            cred = row.get("credential_id")
            if cred:
                credential_agents[cred].add(row["agent_id"])
                credential_lines[cred].append((tool_call_id, line_number))
    shared_credentials = sorted(
        cred for cred, agents_set in credential_agents.items()
        if len(agents_set) > 1
    )

    coordinator_ranking = [
        {"agent_id": agent, "assignment_count": count}
        for agent, count in assignment_counts.most_common()
    ]
    detected_coordinators = {
        item["agent_id"] for item in coordinator_ranking
        if item["assignment_count"] >= coordinator_min_assignments
    }
    tool_mismatch_reasons = {"tool-name-mismatch", "argument-digest-mismatch"}
    detected_spoofs = {
        item["tool_call_id"] for item in findings
        if tool_mismatch_reasons & set(item["reasons"])
    }
    detected_unbacked = {
        item["tool_call_id"] for item in findings
        if "unbacked-completion" in item["reasons"]
    }
    detected_oracle = {
        item["tool_call_id"] for item in findings
        if "oracle-integrity-violation" in item["reasons"]
    }

    timeline_finding_count = sum(1 for e in timeline_events if e["event_type"] == "finding")
    timeline_assignment_count = sum(1 for e in timeline_events if e["event_type"] == "coordinator-assignment")

    reason_counts = Counter(reason for item in findings for reason in item["reasons"])
    confidence_bands = Counter(_confidence_label(item["confidence_score"]) for item in findings)
    avg_confidence = round(sum(item["confidence_score"] for item in findings) / len(findings), 3) if findings else 0.0
    mitre_counts: Counter[str] = Counter()
    for item in findings:
        for technique in item.get("mitre_techniques", []):
            mitre_counts[f"{technique['id']} {technique['name']}"] += 1
    summary = {
        "synthetic": True,
        "scenario": "Synthetic cross-agent coordination and transcript/control-plane inconsistency exercise",
        "corpus": {
            "agents": len(all_agents),
            "messages": message_count,
            "transcripts": sum(len(rows) for rows in transcripts_by_call.values()),
            "control_plane_events": sum(len(rows) for rows in controls_by_call.values()),
            "first_timestamp": min(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
            "last_timestamp": max(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
        },
        "findings": {
            "unsanctioned_board_messages": board_message_count,
            "board_participants": len(board_participants),
            "transcript_tool_call_mismatches": len(detected_spoofs),
            "unbacked_completions": len(detected_unbacked),
            "oracle_integrity_violations": len(detected_oracle),
            "record_conflicts": len(findings),
            "missing_transcripts": reason_counts["missing-transcript"],
            "missing_control_plane_events": reason_counts["missing-control-plane-event"],
            "duplicate_tool_call_identifiers": (
                reason_counts["duplicate-transcript-tool-call-id"]
                + reason_counts["duplicate-control-tool-call-id"]
            ),
            "identity_or_trace_conflicts": (
                reason_counts["agent-id-mismatch"] + reason_counts["trace-id-mismatch"]
            ),
            "duplicate_message_identifiers": len(duplicate_message_ids),
            "top_coordinators": [item["agent_id"] for item in coordinator_ranking[:10]],
            "coordinators_over_threshold": len(detected_coordinators),
            "trajectory_records": len(trajectories),
            "shared_credentials": len(shared_credentials),
            "reason_counts": dict(sorted(reason_counts.items())),
            "confidence_bands": {"high": confidence_bands.get("high", 0), "medium": confidence_bands.get("medium", 0), "low": confidence_bands.get("low", 0)},
            "average_confidence_score": avg_confidence,
            "mitre_technique_counts": dict(sorted(mitre_counts.items())),
            "timeline_events": len(timeline_events),
            "timeline_finding_events": timeline_finding_count,
            "timeline_assignment_events": timeline_assignment_count,
        },
        "method": {
            "authoritative_source": "control_plane.jsonl for executed tool activity",
            "untrusted_source": "transcripts.jsonl",
            "coordinator_threshold": f"at least {coordinator_min_assignments} observed assignment events",
            "evidence_controls": [
                "SHA-256 manifest", "stable IDs", "UTC timestamps",
                "source file and line references", "duplicate and missing-record detection",
            ],
            "llm_boundary": "No LLM is used for factual extraction, joins, integrity checks, or findings. An LLM may summarize already-cited findings only.",
            "ground_truth_dependency": "none; an optional fixture is used only after detections for evaluation",
        },
        "limitations": [
            "All data is synthetic and structurally cleaner than production telemetry.",
            "Stable tool-call identifiers make reconciliation easier than in many real environments.",
            "The coordinator threshold is explicit and scenario-specific, not a claim about intent.",
            "Hash manifests prove post-acquisition integrity, not the truthfulness of the originating system.",
            "The lab demonstrates investigation mechanics, not frontier-model interpretability or RL post-training expertise.",
        ],
        "runtime_seconds": round(time.perf_counter() - started, 3),
    }

    if ground_truth_path is not None:
        truth = _load_ground_truth(ground_truth_path)
        summary["evaluation"] = {
            "spoof_detection": _prf(detected_spoofs, set(truth["spoofed_tool_call_ids"])),
            "participant_detection": _prf(board_participants, set(truth["participating_agents"])),
            "coordinator_detection": _prf(detected_coordinators, set(truth["coordinators"])),
            "unbacked_completion_detection": _prf(detected_unbacked, set(truth.get("unbacked_completion_tool_call_ids", []))),
            "oracle_modification_detection": _prf(detected_oracle, set(truth.get("oracle_modification_tool_call_ids", []))),
            "credential_reuse_detection": _prf(set(shared_credentials), set(truth.get("shared_credential_ids", []))),
            "interpretation": "The evaluation fixture was consulted only after detections were complete. Scores measure recovery on generated data, not expected production accuracy.",
        }

    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "findings.json").write_text(
        json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "trajectories.json").write_text(
        json.dumps(trajectories, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "coordinator_ranking.json").write_text(
        json.dumps(coordinator_ranking, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    missing_transcript_ids = sorted(
        tcid for tcid, items in controls_by_call.items()
        if tcid not in transcripts_by_call
    )
    missing_control_ids = sorted(
        tcid for tcid, items in transcripts_by_call.items()
        if tcid not in controls_by_call
    )
    duplicate_transcript_ids = sorted(
        tcid for tcid, items in transcripts_by_call.items()
        if len(items) > 1
    )
    duplicate_control_ids = sorted(
        tcid for tcid, items in controls_by_call.items()
        if len(items) > 1
    )
    data_quality = {
        "duplicate_message_ids": duplicate_message_ids,
        "missing_transcript_ids": missing_transcript_ids,
        "missing_control_plane_ids": missing_control_ids,
        "duplicate_transcript_tool_call_ids": duplicate_transcript_ids,
        "duplicate_control_tool_call_ids": duplicate_control_ids,
    }
    (output_dir / "data_quality.json").write_text(
        json.dumps(data_quality, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    credential_reuse_records = [
        {
            "credential_id": cred,
            "agent_count": len(credential_agents[cred]),
            "agents": sorted(credential_agents[cred]),
        }
        for cred in shared_credentials
    ]
    (output_dir / "credential_reuse.json").write_text(
        json.dumps(credential_reuse_records, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "timeline.json").write_text(
        json.dumps(timeline_events, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )

    fieldnames = (
        "finding_id", "tool_call_id", "agent_id_transcript", "agent_id_control",
        "trace_id_transcript", "trace_id_control", "reasons", "mitre_techniques",
        "transcript_source", "transcript_line", "control_source", "control_line",
        "claimed_tool", "actual_tool", "effect", "confidence", "confidence_score",
    )
    with (output_dir / "findings.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings:
            row = dict(item)
            row["reasons"] = ";".join(row["reasons"])
            row["mitre_techniques"] = ";".join(
                f"{t['id']}:{t['name']}" for t in row.get("mitre_techniques", [])
            )
            writer.writerow({key: row.get(key) for key in fieldnames})

    report = _render_report(summary, evidence_manifest, timeline_events, data_quality)
    (output_dir / "report.md").write_text(report, encoding="utf-8")
    return summary


def _render_mitre_section(findings_summary: dict) -> str:
    counts = findings_summary.get("mitre_technique_counts", {})
    if not counts:
        return ""
    rows = []
    for key, count in sorted(counts.items()):
        tid, name = key.split(" ", 1)
        rows.append(f"| {tid} | {name} | {count} |")
    return f"""## MITRE ATT&CK mapping

| Technique ID | Name | Findings |
| --- | --- | ---: |
{chr(10).join(rows)}

Mappings are deterministic: each detection reason maps to a fixed ATT&CK technique. A finding with multiple reasons may map to multiple techniques.
"""


def _render_timeline(events: list[dict]) -> str:
    if not events:
        return ""
    finding_events = [e for e in events if e["event_type"] == "finding"]
    assignment_events = [e for e in events if e["event_type"] == "coordinator-assignment"]
    lines = ["## Timeline", ""]
    if assignment_events:
        lines.append(f"### Coordinator assignments ({len(assignment_events):,} events)")
        lines.append("")
        shown = assignment_events[:20]
        for e in shown:
            ts = e["timestamp"].replace("T", " ").replace("Z", " UTC").rstrip()
            lines.append(f"- `{ts}` **{e['agent_id']}**: {e['detail']}")
        if len(assignment_events) > 20:
            lines.append(f"- ... and {len(assignment_events) - 20:,} more coordinator assignments")
        lines.append("")
    if finding_events:
        lines.append(f"### Finding-linked events ({len(finding_events):,} events)")
        lines.append("")
        for e in finding_events:
            ts = e["timestamp"].replace("T", " ").replace("Z", " UTC").rstrip()
            fid = e.get("finding_id", "")
            lines.append(f"- `{ts}` **{e['agent_id']}** [{fid}]: {e['detail']}")
        lines.append("")
    hour_buckets: dict[str, int] = {}
    for e in events:
        hour = e["timestamp"][:13]
        hour_buckets[hour] = hour_buckets.get(hour, 0) + 1
    if len(hour_buckets) > 1:
        lines.append("### Activity by hour")
        lines.append("")
        lines.append("| Hour (UTC) | Events |")
        lines.append("| --- | ---: |")
        for hour in sorted(hour_buckets):
            display = hour.replace("T", " ") + ":00"
            lines.append(f"| {display} | {hour_buckets[hour]:,} |")
        lines.append("")
    lines.append("Full event data is in `timeline.json`.")
    lines.append("")
    return "\n".join(lines)


def _render_data_quality(data_quality: dict) -> str:
    dup_msgs = len(data_quality.get("duplicate_message_ids", []))
    missing_tx = len(data_quality.get("missing_transcript_ids", []))
    missing_cp = len(data_quality.get("missing_control_plane_ids", []))
    dup_tx = len(data_quality.get("duplicate_transcript_tool_call_ids", []))
    dup_cp = len(data_quality.get("duplicate_control_tool_call_ids", []))
    total = dup_msgs + missing_tx + missing_cp + dup_tx + dup_cp
    if total == 0:
        return "## Data quality\n\nNo duplicate IDs, missing records, or duplicate tool-call IDs detected.\n"
    rows = []
    if dup_msgs:
        rows.append(f"| Duplicate message IDs | {dup_msgs:,} |")
    if missing_tx:
        rows.append(f"| Missing transcript records | {missing_tx:,} |")
    if missing_cp:
        rows.append(f"| Missing control-plane records | {missing_cp:,} |")
    if dup_tx:
        rows.append(f"| Duplicate transcript tool-call IDs | {dup_tx:,} |")
    if dup_cp:
        rows.append(f"| Duplicate control-plane tool-call IDs | {dup_cp:,} |")
    return f"""## Data quality

| Check | Count |
| --- | ---: |
{chr(10).join(rows)}

{total:,} total data-quality issue(s). Full details are in `data_quality.json`.
"""


def _render_statistics_table(findings_summary: dict) -> str:
    reason_counts = findings_summary.get("reason_counts", {})
    bands = findings_summary.get("confidence_bands", {})
    avg = findings_summary.get("average_confidence_score", 0.0)
    if not reason_counts and not bands:
        return ""
    lines = ["## Finding statistics", ""]
    if reason_counts:
        lines.append("### By detection type")
        lines.append("")
        lines.append("| Detection type | Count |")
        lines.append("| --- | ---: |")
        for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {reason} | {count:,} |")
        lines.append("")
    if bands:
        total = sum(bands.values())
        lines.append("### By confidence band")
        lines.append("")
        lines.append("| Band | Count | Share |")
        lines.append("| --- | ---: | ---: |")
        for band in ("high", "medium", "low"):
            c = bands.get(band, 0)
            pct = f"{100 * c / total:.1f}%" if total > 0 else "0.0%"
            lines.append(f"| {band} | {c:,} | {pct} |")
        lines.append(f"| **total** | **{total:,}** | |")
        lines.append("")
        lines.append(f"Average confidence score: **{avg:.3f}**")
        lines.append("")
    lines.append("Confidence scoring: a finding backed by both transcript and control-plane evidence with multiple corroborating conflicts scores highest. Duplicate records reduce confidence.")
    lines.append("")
    return "\n".join(lines)


def _render_report(summary: dict, manifest: dict, timeline_events: list[dict] | None = None, data_quality: dict | None = None) -> str:
    corpus = summary["corpus"]
    findings = summary["findings"]
    files = "\n".join(
        f"- `{item['name']}` ({item['role']}): `{item['sha256']}` ({item['bytes']:,} bytes)"
        for item in manifest["files"]
    )
    if "evaluation" in summary:
        evaluation = summary["evaluation"]
        evaluation_section = f"""## Evaluation against an optional synthetic fixture

| Detection | Precision | Recall | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transcript/tool mismatch | {evaluation['spoof_detection']['precision']:.4f} | {evaluation['spoof_detection']['recall']:.4f} | {evaluation['spoof_detection']['true_positive']} | {evaluation['spoof_detection']['false_positive']} | {evaluation['spoof_detection']['false_negative']} |
| Channel participation | {evaluation['participant_detection']['precision']:.4f} | {evaluation['participant_detection']['recall']:.4f} | {evaluation['participant_detection']['true_positive']} | {evaluation['participant_detection']['false_positive']} | {evaluation['participant_detection']['false_negative']} |
| Coordinator threshold | {evaluation['coordinator_detection']['precision']:.4f} | {evaluation['coordinator_detection']['recall']:.4f} | {evaluation['coordinator_detection']['true_positive']} | {evaluation['coordinator_detection']['false_positive']} | {evaluation['coordinator_detection']['false_negative']} |
| Unbacked completion | {evaluation['unbacked_completion_detection']['precision']:.4f} | {evaluation['unbacked_completion_detection']['recall']:.4f} | {evaluation['unbacked_completion_detection']['true_positive']} | {evaluation['unbacked_completion_detection']['false_positive']} | {evaluation['unbacked_completion_detection']['false_negative']} |
| Oracle integrity | {evaluation['oracle_modification_detection']['precision']:.4f} | {evaluation['oracle_modification_detection']['recall']:.4f} | {evaluation['oracle_modification_detection']['true_positive']} | {evaluation['oracle_modification_detection']['false_positive']} | {evaluation['oracle_modification_detection']['false_negative']} |
| Credential reuse | {evaluation['credential_reuse_detection']['precision']:.4f} | {evaluation['credential_reuse_detection']['recall']:.4f} | {evaluation['credential_reuse_detection']['true_positive']} | {evaluation['credential_reuse_detection']['false_positive']} | {evaluation['credential_reuse_detection']['false_negative']} |

The fixture is consulted only after detection. It does not determine the findings or the number of coordinators reported.
"""
    else:
        evaluation_section = """## Evaluation

No answer key was supplied. Findings were produced from the three evidence sources alone.
"""

    return f"""# ORBIT Synthetic Agent Incident Reconstruction

## Scope statement

This is a reproducible synthetic exercise. It does not claim access to or experience with a frontier lab incident. It demonstrates evidence preservation, independent log reconciliation, cross-agent coordination analysis, trajectory construction, and explicit limitations.

## Corpus

- {corpus['agents']:,} observed agents
- {corpus['messages']:,} message events
- {corpus['transcripts']:,} transcript records
- {corpus['control_plane_events']:,} independent control-plane events
- UTC window: {corpus['first_timestamp']} to {corpus['last_timestamp']}

## Decision-grade findings

1. {findings['board_participants']:,} agents used an unsanctioned coordination channel, producing {findings['unsanctioned_board_messages']:,} events.
2. Independent control-plane evidence contradicted {findings['transcript_tool_call_mismatches']:,} transcript tool-call records.
5. {findings['unbacked_completions']:,} tool calls claimed completion but their independent check failed (unbacked completions).
6. {findings['oracle_integrity_violations']:,} tool calls modified protected test expectations (oracle integrity violations).
7. {findings['shared_credentials']:,} workload credentials were used by more than one agent (credential reuse).
3. The pipeline reported {findings['record_conflicts']:,} total record conflicts and reconstructed {findings['trajectory_records']:,} source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

{_render_statistics_table(findings)}
{_render_timeline(timeline_events or [])}
{_render_mitre_section(findings)}
{_render_data_quality(data_quality or {})}
{evaluation_section}
## Evidence model

`workload identity -> agent -> tool call -> credential -> resource -> effect -> control decision`

Transcripts are treated as potentially untrusted. Factual findings require independent control-plane support. The pipeline writes SHA-256 hashes, exact source lines, UTC timestamps, confidence, and the basis for each reconstructed trajectory.

## LLM boundary

No LLM is used for extraction, joins, hashes, mismatch detection, or findings. An LLM may summarize findings only after the deterministic pipeline has produced source-linked records.

## Limitations

{chr(10).join(f'- {item}' for item in summary['limitations'])}

## Evidence manifest

{files}

Runtime on the generating system: {summary['runtime_seconds']:.3f} seconds. Runtime is informational and hardware-dependent.
"""
