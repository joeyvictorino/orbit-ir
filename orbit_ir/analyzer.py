from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")
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


def _finding(
    finding_number: int,
    tool_call_id: str,
    transcripts: list[tuple[int, dict]],
    controls: list[tuple[int, dict]],
    reasons: list[str],
) -> dict:
    transcript = _first(transcripts)
    control = _first(controls)
    return {
        "finding_id": f"finding-{finding_number:06d}",
        "tool_call_id": tool_call_id,
        "agent_id_transcript": transcript.get("agent_id"),
        "agent_id_control": control.get("agent_id"),
        "trace_id_transcript": transcript.get("trace_id"),
        "trace_id_control": control.get("trace_id"),
        "reasons": reasons,
        "transcript_source": "transcripts.jsonl" if transcripts else None,
        "transcript_line": _source_lines(transcripts) if transcripts else None,
        "control_source": "control_plane.jsonl" if controls else None,
        "control_line": _source_lines(controls) if controls else None,
        "claimed_tool": transcript.get("claimed_tool"),
        "actual_tool": control.get("actual_tool"),
        "effect": control.get("effect"),
        "confidence": "medium" if any(reason.startswith("duplicate-") for reason in reasons) else "high",
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

    for line_number, event in _iter_jsonl(input_dir / "messages.jsonl"):
        message_count += 1
        timestamps.append(_parse_timestamp(event["timestamp"], f"messages.jsonl:{line_number}"))
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

    reason_counts = Counter(reason for item in findings for reason in item["reasons"])
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
            "reason_counts": dict(sorted(reason_counts.items())),
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
            "interpretation": "The evaluation fixture was consulted only after detections were complete. Scores measure recovery on generated data, not expected production accuracy.",
        }

    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "trajectories.json").write_text(
        json.dumps(trajectories, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "coordinator_ranking.json").write_text(
        json.dumps(coordinator_ranking, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "data_quality.json").write_text(
        json.dumps({"duplicate_message_ids": duplicate_message_ids}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    fieldnames = (
        "finding_id", "tool_call_id", "agent_id_transcript", "agent_id_control",
        "trace_id_transcript", "trace_id_control", "reasons", "transcript_source",
        "transcript_line", "control_source", "control_line", "claimed_tool",
        "actual_tool", "effect", "confidence",
    )
    with (output_dir / "findings.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings:
            row = dict(item)
            row["reasons"] = ";".join(row["reasons"])
            writer.writerow({key: row.get(key) for key in fieldnames})

    report = _render_report(summary, evidence_manifest)
    (output_dir / "report.md").write_text(report, encoding="utf-8")
    return summary


def _render_report(summary: dict, manifest: dict) -> str:
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
3. The pipeline reported {findings['record_conflicts']:,} total record conflicts and reconstructed {findings['trajectory_records']:,} source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

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
