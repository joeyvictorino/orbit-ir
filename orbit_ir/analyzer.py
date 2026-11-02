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
    "lateral-resource-access": {"id": "T1021", "name": "Remote Services"},
}

REASON_SEVERITY: dict[str, str] = {
    "tool-name-mismatch": "critical",
    "argument-digest-mismatch": "critical",
    "lateral-resource-access": "high",
    "unbacked-completion": "high",
    "oracle-integrity-violation": "high",
    "agent-id-mismatch": "medium",
    "trace-id-mismatch": "medium",
    "missing-transcript": "medium",
    "missing-control-plane-event": "medium",
    "shared-credential": "low",
    "duplicate-transcript": "low",
    "duplicate-control-event": "low",
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _finding_severity(reasons: list[str]) -> str:
    best = 0
    for r in reasons:
        best = max(best, SEVERITY_ORDER.get(REASON_SEVERITY.get(r, "low"), 0))
    for label, rank in SEVERITY_ORDER.items():
        if rank == best:
            return label
    return "low"

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


_DETECTION_WEIGHTS: dict[str, float] = {
    "spoofed_tool_calls": 30.0,
    "lateral_movement": 25.0,
    "unbacked_completions": 20.0,
    "oracle_violations": 20.0,
    "identity_trace_conflicts": 15.0,
    "missing_records": 10.0,
    "shared_credentials": 5.0,
}


def _composite_risk_score(
    *,
    spoofed: int,
    lateral: int,
    unbacked: int,
    oracle: int,
    identity_trace: int,
    missing: int,
    shared_creds: int,
    total_transcripts: int,
) -> dict:
    if total_transcripts == 0:
        return {"score": 0, "rating": "none", "components": {}}
    components: dict[str, float] = {}
    raw = 0.0
    for name, count in [
        ("spoofed_tool_calls", spoofed),
        ("lateral_movement", lateral),
        ("unbacked_completions", unbacked),
        ("oracle_violations", oracle),
        ("identity_trace_conflicts", identity_trace),
        ("missing_records", missing),
        ("shared_credentials", shared_creds),
    ]:
        w = _DETECTION_WEIGHTS[name]
        fraction = min(count / max(total_transcripts, 1), 1.0)
        component = w * fraction
        components[name] = round(component, 2)
        raw += component
    score = round(min(raw / sum(_DETECTION_WEIGHTS.values()) * 100, 100), 1)
    if score >= 75:
        rating = "critical"
    elif score >= 50:
        rating = "high"
    elif score >= 25:
        rating = "medium"
    elif score > 0:
        rating = "low"
    else:
        rating = "none"
    return {"score": score, "rating": rating, "components": components}


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
        "severity": _finding_severity(reasons),
        "confidence": _confidence_label(score),
        "confidence_score": score,
    }


CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def filter_findings(
    findings: list[dict],
    *,
    min_confidence: str | None = None,
    min_severity: str | None = None,
    detection_types: list[str] | None = None,
    agents: list[str] | None = None,
) -> list[dict]:
    """Filter a findings list by confidence, severity, detection type, and/or agent."""
    result = findings
    if min_severity is not None:
        threshold = SEVERITY_ORDER.get(min_severity, 0)
        result = [
            f for f in result
            if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= threshold
        ]
    if min_confidence is not None:
        threshold = CONFIDENCE_ORDER.get(min_confidence, 0)
        result = [
            f for f in result
            if CONFIDENCE_ORDER.get(f.get("confidence", "low"), 0) >= threshold
        ]
    if detection_types is not None:
        type_set = set(detection_types)
        result = [
            f for f in result
            if type_set & set(f.get("reasons", []))
        ]
    if agents is not None:
        agent_set = set(agents)
        result = [
            f for f in result
            if f.get("agent_id_transcript") in agent_set
            or f.get("agent_id_control") in agent_set
        ]
    return result


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
    board_edges: list[tuple[str, str]] = []
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
                board_edges.append((event["agent_id"], event["recipient_agent_id"]))
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

    agent_clusters = _detect_agent_clusters(credential_agents, board_edges, all_agents)

    lateral_movement = _detect_lateral_movement(controls_by_call)
    detected_lateral_ids = {f["tool_call_id"] for f in lateral_movement}
    for lm in lateral_movement:
        timeline_events.append({
            "timestamp": lm["timestamp"],
            "agent_id": lm["agent_id"],
            "source": "control_plane.jsonl",
            "line": lm["source_line"],
            "event_type": "lateral-movement",
            "detail": f"accessed {lm['resource']} (assigned to {lm['resource_owner']})",
        })

    timeline_events.sort(key=lambda e: (e["timestamp"], e["agent_id"]))

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

    total_transcripts = sum(len(rows) for rows in transcripts_by_call.values())
    risk = _composite_risk_score(
        spoofed=len(detected_spoofs),
        lateral=len(lateral_movement),
        unbacked=len(detected_unbacked),
        oracle=len(detected_oracle),
        identity_trace=reason_counts["agent-id-mismatch"] + reason_counts["trace-id-mismatch"],
        missing=reason_counts["missing-transcript"] + reason_counts["missing-control-plane-event"],
        shared_creds=len(shared_credentials),
        total_transcripts=total_transcripts,
    )

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
            "agent_clusters": len(agent_clusters),
            "lateral_movement_detections": len(lateral_movement),
            "reason_counts": dict(sorted(reason_counts.items())),
            "confidence_bands": {"high": confidence_bands.get("high", 0), "medium": confidence_bands.get("medium", 0), "low": confidence_bands.get("low", 0)},
            "average_confidence_score": avg_confidence,
            "mitre_technique_counts": dict(sorted(mitre_counts.items())),
            "timeline_events": len(timeline_events),
            "timeline_finding_events": timeline_finding_count,
            "timeline_assignment_events": timeline_assignment_count,
            "risk_score": risk["score"],
            "risk_rating": risk["rating"],
            "risk_components": risk["components"],
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
            "lateral_movement_detection": _prf(detected_lateral_ids, set(truth.get("lateral_access_tool_call_ids", []))),
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
    (output_dir / "clusters.json").write_text(
        json.dumps(agent_clusters, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "lateral_movement.json").write_text(
        json.dumps(lateral_movement, indent=2, sort_keys=True) + "\n",
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

    from .sarif import write_sarif

    write_sarif(
        findings,
        output_dir / "findings.sarif",
        lateral_movement=lateral_movement,
        input_dir=input_dir,
    )

    report = _render_report(summary, evidence_manifest, timeline_events, data_quality, trajectories, agent_clusters, lateral_movement)
    (output_dir / "report.md").write_text(report, encoding="utf-8")

    from .html_report import render_html_report

    html_content = render_html_report(report, title=f"ORBIT Analysis — {output_dir.name}")
    (output_dir / "report.html").write_text(html_content, encoding="utf-8")
    return summary


def verify_evidence(
    input_dir: Path,
    manifest_path: Path | None = None,
) -> dict:
    """Verify evidence files against a SHA-256 manifest.

    Returns a dict with a ``files`` list.  Each entry has ``name``,
    ``status`` (``ok``, ``mismatch``, ``missing``, ``extra``), and
    ``detail``.
    """
    if manifest_path is None:
        candidate = input_dir.parent / "results" / "evidence_manifest.json"
        if candidate.is_file():
            manifest_path = candidate

    if manifest_path is not None and manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {f["name"]: f for f in manifest["files"]}
    else:
        expected = {name: None for name in EVIDENCE_FILES}

    results: list[dict] = []
    seen: set[str] = set()

    for name in sorted(expected):
        seen.add(name)
        path = input_dir / name
        if not path.is_file():
            results.append({"name": name, "status": "missing", "detail": "file not found"})
            continue
        actual_hash = _sha256(path)
        actual_size = path.stat().st_size
        exp = expected[name]
        if exp is not None and exp.get("sha256"):
            if actual_hash == exp["sha256"]:
                results.append({"name": name, "status": "ok", "detail": f"sha256={actual_hash[:16]}... ({actual_size:,} bytes)"})
            else:
                results.append({
                    "name": name,
                    "status": "mismatch",
                    "detail": f"expected sha256={exp['sha256'][:16]}..., got {actual_hash[:16]}...",
                })
        else:
            results.append({"name": name, "status": "ok", "detail": f"sha256={actual_hash[:16]}... ({actual_size:,} bytes, no manifest to compare)"})

    for child in sorted(input_dir.iterdir()):
        if child.name not in seen and child.is_file() and child.suffix == ".jsonl":
            results.append({"name": child.name, "status": "extra", "detail": "not in manifest"})

    return {"files": results}


def _render_trajectory_graph(trajectories: list[dict]) -> str:
    if not trajectories:
        return ""
    lines = ["## Agent trajectory graph", "", "```mermaid", "flowchart LR"]
    agents: dict[str, list[dict]] = {}
    for traj in trajectories:
        path = traj.get("path", [])
        agent_node = next((n for n in path if n["type"] == "agent"), None)
        if agent_node:
            agents.setdefault(agent_node["id"], []).append(traj)
    node_counter = 0
    confidence_styles: dict[str, str] = {}
    for agent_id in sorted(agents):
        trajs = agents[agent_id]
        safe_agent = agent_id.replace("-", "_").replace(".", "_")
        lines.append(f"    subgraph {safe_agent}[\"{agent_id}\"]")
        for traj in trajs:
            path = traj.get("path", [])
            confidence = traj.get("confidence", "low")
            tool_node = next((n for n in path if n["type"] == "tool_call"), None)
            resource_node = next((n for n in path if n["type"] == "resource"), None)
            effect_node = next((n for n in path if n["type"] == "effect"), None)
            decision_node = next((n for n in path if n["type"] == "control_decision"), None)
            if not tool_node:
                continue
            tid = f"n{node_counter}"; node_counter += 1
            rid = f"n{node_counter}"; node_counter += 1
            eid = f"n{node_counter}"; node_counter += 1
            tool_label = tool_node["id"][:30]
            res_label = (resource_node["id"] if resource_node else "?")[:30]
            eff_label = (effect_node["id"] if effect_node else "?")[:20]
            dec_label = (decision_node["id"] if decision_node else "?")[:10]
            lines.append(f"        {tid}[\"{tool_label}\"] --> {rid}[\"{res_label}\"]")
            lines.append(f"        {rid} --> {eid}[\"{eff_label} / {dec_label}\"]")
            confidence_styles[tid] = confidence
            confidence_styles[eid] = confidence
        lines.append("    end")
    high_nodes = [k for k, v in confidence_styles.items() if v == "high"]
    med_nodes = [k for k, v in confidence_styles.items() if v == "medium"]
    low_nodes = [k for k, v in confidence_styles.items() if v == "low"]
    if high_nodes:
        lines.append(f"    style {','.join(high_nodes)} fill:#d32f2f,color:#fff")
    if med_nodes:
        lines.append(f"    style {','.join(med_nodes)} fill:#f57c00,color:#fff")
    if low_nodes:
        lines.append(f"    style {','.join(low_nodes)} fill:#757575,color:#fff")
    lines.append("```")
    lines.append("")
    lines.append(f"{len(trajectories):,} trajectories across {len(agents):,} agents. "
                 "Red = high confidence, orange = medium, grey = low. "
                 "Full trajectory data is in `trajectories.json`.")
    lines.append("")
    return "\n".join(lines)


def _detect_agent_clusters(
    credential_agents: dict[str, set[str]],
    board_edges: list[tuple[str, str]],
    all_agents: set[str],
) -> list[dict]:
    parent: dict[str, str] = {a: a for a in all_agents}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for cred, agents_set in credential_agents.items():
        agents_list = sorted(agents_set)
        for i in range(1, len(agents_list)):
            union(agents_list[0], agents_list[i])

    for a, b in board_edges:
        if a in parent and b in parent:
            union(a, b)

    groups: dict[str, set[str]] = defaultdict(set)
    for agent in all_agents:
        groups[find(agent)].add(agent)

    edge_counts: Counter[tuple[str, ...]] = Counter()
    for a, b in board_edges:
        key = tuple(sorted([a, b]))
        edge_counts[key] += 1

    clusters = []
    for root, members in sorted(groups.items(), key=lambda x: -len(x[1])):
        if len(members) < 2:
            continue
        shared = sorted(
            cred for cred, agents_set in credential_agents.items()
            if len(agents_set & members) > 1
        )
        board_msg_count = sum(
            count for (a, b), count in edge_counts.items()
            if a in members and b in members
        )
        clusters.append({
            "agents": sorted(members),
            "shared_credentials": shared,
            "board_messages": board_msg_count,
            "size": len(members),
        })
    return clusters


def _detect_lateral_movement(
    controls_by_call: dict[str, list[tuple[int, dict]]],
) -> list[dict]:
    """Detect agents accessing resources assigned to different agents.

    A control-plane event with a ``resource_owner`` field that differs from
    the acting ``agent_id`` is a lateral resource access.
    """
    findings: list[dict] = []
    for tool_call_id, controls in sorted(controls_by_call.items()):
        for line_number, row in controls:
            owner = row.get("resource_owner")
            if owner is None:
                continue
            if row["agent_id"] == owner:
                continue
            findings.append({
                "tool_call_id": tool_call_id,
                "agent_id": row["agent_id"],
                "resource": row.get("resource", "unknown"),
                "resource_owner": owner,
                "timestamp": row["timestamp"],
                "effect": row.get("effect", "unknown"),
                "source_line": line_number,
                "severity": "high",
            })
    return findings


def _render_lateral_movement(lateral_findings: list[dict]) -> str:
    if not lateral_findings:
        return ""
    lines = ["## Lateral movement", ""]
    lines.append(
        f"{len(lateral_findings):,} instance(s) of an agent accessing a resource "
        "assigned to a different agent."
    )
    lines.append("")
    lines.append("| Agent | Resource | Assigned to | Effect | Source |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in lateral_findings[:25]:
        lines.append(
            f"| {f['agent_id']} | {f['resource']} | {f['resource_owner']} "
            f"| {f['effect']} | control_plane.jsonl:{f['source_line']} |"
        )
    if len(lateral_findings) > 25:
        lines.append(f"| ... | ... | ... | ... | +{len(lateral_findings) - 25:,} more |")
    lines.append("")
    lines.append(
        "Lateral resource access means an agent used a resource explicitly "
        "assigned to another agent's workload. Full data is in `lateral_movement.json`."
    )
    lines.append("")
    return "\n".join(lines)


def _render_clusters(clusters: list[dict]) -> str:
    if not clusters:
        return ""
    lines = ["## Agent clusters", ""]
    lines.append(f"{len(clusters):,} cluster(s) of agents linked by shared credentials or board communication.")
    lines.append("")
    lines.append("| Cluster | Agents | Shared credentials | Board messages |")
    lines.append("| --- | ---: | ---: | ---: |")
    for i, c in enumerate(clusters, 1):
        agent_list = ", ".join(c["agents"][:5])
        if len(c["agents"]) > 5:
            agent_list += f" (+{len(c['agents']) - 5})"
        lines.append(f"| C{i} | {c['size']:,} ({agent_list}) | {len(c['shared_credentials']):,} | {c['board_messages']:,} |")
    lines.append("")
    lines.append("Clusters are connected components in a graph where edges are shared credentials and board messages. Full data is in `clusters.json`.")
    lines.append("")
    return "\n".join(lines)


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


_DETECTION_METHODOLOGY: dict[str, dict[str, str]] = {
    "tool-name-mismatch": {
        "description": "Compares the tool name claimed in the agent transcript against the actual tool name recorded by the independent control plane for the same tool_call_id.",
        "evidence": "transcripts.jsonl (claimed_tool) vs. control_plane.jsonl (actual_tool)",
        "implication": "The agent misrepresented which tool it called, potentially to hide a destructive or unauthorized operation behind a benign-looking name.",
    },
    "argument-digest-mismatch": {
        "description": "Compares SHA-256 digests of claimed vs. actual arguments for matched tool calls.",
        "evidence": "transcripts.jsonl (claimed_args_digest) vs. control_plane.jsonl (actual_args_digest)",
        "implication": "The agent passed different arguments than it reported, possibly to conceal the true parameters of an operation.",
    },
    "unbacked-completion": {
        "description": "Detects tool calls where the agent claimed task completion but the independent verification check did not pass.",
        "evidence": "transcripts.jsonl (tool_call_id) vs. control_plane.jsonl (policy_decision)",
        "implication": "The agent reported success without the work actually being done or verified, undermining task reliability.",
    },
    "oracle-integrity-violation": {
        "description": "Detects writes to protected test expectation files (tests/, spec/, fixtures/) that serve as oracle data for the validation pipeline.",
        "evidence": "control_plane.jsonl (resource path, effect=write)",
        "implication": "Modifying oracle expectations can make failing tests pass, subverting the entire verification system.",
    },
    "agent-id-mismatch": {
        "description": "Compares the agent_id in the transcript against the agent_id in the control-plane record for the same tool call.",
        "evidence": "transcripts.jsonl (agent_id) vs. control_plane.jsonl (agent_id)",
        "implication": "Identity confusion or impersonation: one agent's actions are attributed to another.",
    },
    "trace-id-mismatch": {
        "description": "Compares trace_id values between transcript and control-plane records for matched tool calls.",
        "evidence": "transcripts.jsonl (trace_id) vs. control_plane.jsonl (trace_id)",
        "implication": "Trace chain was broken or tampered with, making it harder to reconstruct the sequence of operations.",
    },
    "missing-transcript": {
        "description": "Finds control-plane events with no matching transcript record (by tool_call_id).",
        "evidence": "control_plane.jsonl tool_call_ids not in transcripts.jsonl",
        "implication": "The agent's own log was suppressed or deleted for these operations, suggesting evidence destruction.",
    },
    "missing-control-plane-event": {
        "description": "Finds transcript records with no matching control-plane event (by tool_call_id).",
        "evidence": "transcripts.jsonl tool_call_ids not in control_plane.jsonl",
        "implication": "Operations claimed in the transcript were never independently observed, or their control-plane records were deleted.",
    },
    "lateral-resource-access": {
        "description": "Detects when an agent accesses resources explicitly assigned to a different agent, based on resource ownership mapping.",
        "evidence": "control_plane.jsonl (agent_id, resource) vs. resource ownership assignments",
        "implication": "Unauthorized cross-boundary access: the agent reached into another agent's domain.",
    },
}


def _render_detection_methodology(findings_summary: dict) -> str:
    fired_reasons: set[str] = set()
    for tc in findings_summary.get("mitre_technique_counts", {}):
        pass
    records = findings_summary.get("trajectory_records", 0)
    mismatches = findings_summary.get("transcript_tool_call_mismatches", 0)
    unbacked = findings_summary.get("unbacked_completions", 0)
    oracle = findings_summary.get("oracle_integrity_violations", 0)
    lateral = findings_summary.get("lateral_movement_detections", 0)

    if mismatches > 0:
        fired_reasons |= {"tool-name-mismatch", "argument-digest-mismatch"}
    if unbacked > 0:
        fired_reasons.add("unbacked-completion")
    if oracle > 0:
        fired_reasons.add("oracle-integrity-violation")
    if lateral > 0:
        fired_reasons.add("lateral-resource-access")
    fired_reasons |= {"agent-id-mismatch", "trace-id-mismatch", "missing-transcript", "missing-control-plane-event"}

    if not fired_reasons:
        return ""

    lines = [
        "## Detection methodology",
        "",
        "Each detection type below ran during this analysis. The table documents what each examines, "
        "what evidence it uses, and what a positive finding means for incident responders.",
        "",
        "| Detection | Evidence sources | What it means |",
        "| --- | --- | --- |",
    ]
    for reason in sorted(fired_reasons):
        meta = _DETECTION_METHODOLOGY.get(reason, {})
        if not meta:
            continue
        mitre = MITRE_TECHNIQUES.get(reason, {})
        mitre_ref = f" ({mitre['id']})" if mitre else ""
        lines.append(
            f"| **{reason}**{mitre_ref} | {meta['evidence']} | {meta['implication']} |"
        )

    lines.append("")
    lines.append("All detections are deterministic and source-linked. No LLM is involved in detection logic.")
    lines.append("")
    return "\n".join(lines)


def _render_report(summary: dict, manifest: dict, timeline_events: list[dict] | None = None, data_quality: dict | None = None, trajectories: list[dict] | None = None, clusters: list[dict] | None = None, lateral_movement: list[dict] | None = None) -> str:
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
| Lateral movement | {evaluation['lateral_movement_detection']['precision']:.4f} | {evaluation['lateral_movement_detection']['recall']:.4f} | {evaluation['lateral_movement_detection']['true_positive']} | {evaluation['lateral_movement_detection']['false_positive']} | {evaluation['lateral_movement_detection']['false_negative']} |

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
8. {findings['lateral_movement_detections']:,} resource accesses crossed agent boundaries (lateral movement).
3. The pipeline reported {findings['record_conflicts']:,} total record conflicts and reconstructed {findings['trajectory_records']:,} source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

## Composite risk score

**{findings['risk_score']}/100 ({findings['risk_rating'].upper()})**

The composite risk score weights detection types by operational severity. Components:

| Category | Weight | Score |
| --- | ---: | ---: |
{chr(10).join(f"| {cat.replace('_', ' ').title()} | {_DETECTION_WEIGHTS[cat]:.0f} | {val:.2f} |" for cat, val in sorted(findings.get('risk_components', {}).items(), key=lambda x: -x[1]))}

{_render_statistics_table(findings)}
{_render_timeline(timeline_events or [])}
{_render_trajectory_graph(trajectories or [])}
{_render_clusters(clusters or [])}
{_render_lateral_movement(lateral_movement or [])}
{_render_mitre_section(findings)}
{_render_data_quality(data_quality or {})}
{evaluation_section}
{_render_detection_methodology(findings)}
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
