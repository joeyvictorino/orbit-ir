from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter
from pathlib import Path


EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl", "ground_truth.json")


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if line.strip():
                yield line_number, json.loads(line)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def analyze_dataset(input_dir: Path, output_dir: Path) -> dict:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE_FILES:
        if not (input_dir / name).exists():
            raise FileNotFoundError(f"missing evidence source: {name}")

    evidence_manifest = {
        "synthetic": True,
        "files": [
            {"name": name, "sha256": _sha256(input_dir / name), "bytes": (input_dir / name).stat().st_size}
            for name in EVIDENCE_FILES
        ],
    }
    (output_dir / "evidence_manifest.json").write_text(
        json.dumps(evidence_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    board_participants: set[str] = set()
    assignment_counts: Counter[str] = Counter()
    message_count = 0
    board_message_count = 0
    first_seen = None
    last_seen = None
    for _, event in _iter_jsonl(input_dir / "messages.jsonl"):
        message_count += 1
        timestamp = event["timestamp"]
        first_seen = timestamp if first_seen is None or timestamp < first_seen else first_seen
        last_seen = timestamp if last_seen is None or timestamp > last_seen else last_seen
        if event["channel"] == "unsanctioned-board":
            board_message_count += 1
            board_participants.add(event["agent_id"])
            if event.get("recipient_agent_id"):
                board_participants.add(event["recipient_agent_id"])
            if event["message_type"] == "assignment":
                assignment_counts[event["agent_id"]] += 1

    transcript_by_call = {row["tool_call_id"]: row for _, row in _iter_jsonl(input_dir / "transcripts.jsonl")}
    mismatches = []
    trajectories = []
    control_count = 0
    for line_number, control in _iter_jsonl(input_dir / "control_plane.jsonl"):
        control_count += 1
        transcript = transcript_by_call.get(control["tool_call_id"])
        if transcript is None:
            mismatches.append({"tool_call_id": control["tool_call_id"], "reason": "missing-transcript"})
            continue
        reasons = []
        if transcript["claimed_tool"] != control["actual_tool"]:
            reasons.append("tool-name-mismatch")
        if transcript["claimed_args_digest"] != control["actual_args_digest"]:
            reasons.append("argument-digest-mismatch")
        if reasons:
            mismatches.append(
                {
                    "tool_call_id": control["tool_call_id"],
                    "agent_id": control["agent_id"],
                    "trace_id": control["trace_id"],
                    "reasons": reasons,
                    "transcript_line": transcript.get("run_id"),
                    "control_plane_line": line_number,
                    "claimed_tool": transcript["claimed_tool"],
                    "actual_tool": control["actual_tool"],
                    "effect": control["effect"],
                    "confidence": "high",
                }
            )
            trajectories.append(
                {
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
                    "confidence": "high",
                    "basis": "stable tool_call_id plus independent control-plane record",
                }
            )

    truth = json.loads((input_dir / "ground_truth.json").read_text(encoding="utf-8"))
    expected_spoofs = set(truth["spoofed_tool_call_ids"])
    detected_spoofs = {item["tool_call_id"] for item in mismatches if item.get("reasons")}
    top_coordinators = [agent for agent, _ in assignment_counts.most_common(truth["config"]["coordinators"])]

    summary = {
        "synthetic": True,
        "scenario": truth["scenario"],
        "corpus": {
            "agents": truth["config"]["agents"],
            "messages": message_count,
            "transcripts": len(transcript_by_call),
            "control_plane_events": control_count,
            "first_timestamp": first_seen,
            "last_timestamp": last_seen,
        },
        "findings": {
            "unsanctioned_board_messages": board_message_count,
            "board_participants": len(board_participants),
            "transcript_tool_call_mismatches": len(detected_spoofs),
            "top_coordinators": top_coordinators,
            "trajectory_records": len(trajectories),
        },
        "evaluation": {
            "spoof_detection": _prf(detected_spoofs, expected_spoofs),
            "participant_detection": _prf(board_participants, set(truth["participating_agents"])),
            "coordinator_detection": _prf(set(top_coordinators), set(truth["coordinators"])),
            "interpretation": "Ground-truth scores measure deterministic correlation on generated data, not expected production accuracy.",
        },
        "method": {
            "authoritative_source": "control_plane.jsonl",
            "untrusted_source": "transcripts.jsonl",
            "evidence_controls": ["SHA-256 manifest", "stable IDs", "UTC timestamps", "source and line references"],
            "llm_boundary": "No LLM is used for factual extraction, joins, integrity checks, or findings. An LLM may summarize already-cited findings only.",
        },
        "limitations": [
            "All data is synthetic and structurally cleaner than production telemetry.",
            "Stable tool-call identifiers make reconciliation easier than in many real environments.",
            "Behavior categories are deterministic labels, not claims about model intent.",
            "The lab demonstrates investigation mechanics, not frontier-model interpretability or RL post-training expertise.",
        ],
        "runtime_seconds": round(time.perf_counter() - started, 3),
    }

    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "trajectories.json").write_text(json.dumps(trajectories, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with (output_dir / "findings.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("tool_call_id", "agent_id", "trace_id", "reasons", "claimed_tool", "actual_tool", "effect", "confidence"),
        )
        writer.writeheader()
        for item in mismatches:
            if item.get("reasons"):
                row = dict(item)
                row["reasons"] = ";".join(row["reasons"])
                writer.writerow({key: row.get(key) for key in writer.fieldnames})

    report = _render_report(summary, evidence_manifest)
    (output_dir / "report.md").write_text(report, encoding="utf-8")
    return summary


def _render_report(summary: dict, manifest: dict) -> str:
    corpus = summary["corpus"]
    findings = summary["findings"]
    evaluation = summary["evaluation"]
    files = "\n".join(
        f"- `{item['name']}`: `{item['sha256']}` ({item['bytes']:,} bytes)" for item in manifest["files"]
    )
    return f"""# ORBIT Synthetic Agent Incident Reconstruction

## Scope statement

This is a reproducible synthetic exercise. It does not claim access to or experience with a frontier lab incident. It demonstrates evidence preservation, independent log reconciliation, cross-agent coordination analysis, trajectory construction, and explicit limitations.

## Corpus

- {corpus['agents']:,} agents
- {corpus['messages']:,} message events
- {corpus['transcripts']:,} transcript records
- {corpus['control_plane_events']:,} independent control-plane events
- UTC window: {corpus['first_timestamp']} to {corpus['last_timestamp']}

## Decision-grade findings

1. {findings['board_participants']:,} agents used an unsanctioned coordination channel, producing {findings['unsanctioned_board_messages']:,} events.
2. Independent control-plane evidence contradicted {findings['transcript_tool_call_mismatches']:,} transcript tool-call records.
3. The pipeline reconstructed {findings['trajectory_records']:,} identity-to-effect trajectories and ranked the highest-volume assignment coordinators.

## Evaluation against synthetic ground truth

| Detection | Precision | Recall | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transcript/tool mismatch | {evaluation['spoof_detection']['precision']:.4f} | {evaluation['spoof_detection']['recall']:.4f} | {evaluation['spoof_detection']['true_positive']} | {evaluation['spoof_detection']['false_positive']} | {evaluation['spoof_detection']['false_negative']} |
| Channel participation | {evaluation['participant_detection']['precision']:.4f} | {evaluation['participant_detection']['recall']:.4f} | {evaluation['participant_detection']['true_positive']} | {evaluation['participant_detection']['false_positive']} | {evaluation['participant_detection']['false_negative']} |
| Coordinator ranking | {evaluation['coordinator_detection']['precision']:.4f} | {evaluation['coordinator_detection']['recall']:.4f} | {evaluation['coordinator_detection']['true_positive']} | {evaluation['coordinator_detection']['false_positive']} | {evaluation['coordinator_detection']['false_negative']} |

These scores validate the implementation against generated labels. They are not production performance claims.

## Evidence model

`workload identity -> agent -> tool call -> credential -> resource -> effect -> control decision`

Transcripts are treated as potentially untrusted. Factual findings require a stable identifier and an independent control-plane record. The pipeline writes SHA-256 hashes, source references, UTC timestamps, confidence, and the basis for each reconstructed trajectory.

## LLM boundary

No LLM is used for extraction, joins, hashes, mismatch detection, or findings. An LLM may summarize findings only after the deterministic pipeline has produced source-linked records.

## Limitations

{chr(10).join(f'- {item}' for item in summary['limitations'])}

## Evidence manifest

{files}

Runtime on the generating system: {summary['runtime_seconds']:.3f} seconds. Runtime is informational and hardware-dependent.
"""
