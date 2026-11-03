"""SARIF 2.1.0 output for orbit-ir findings.

Produces a Static Analysis Results Interchange Format log that can be
uploaded to GitHub Code Scanning via ``gh sarif upload`` or the
``codeql/upload-sarif`` action.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
TOOL_NAME = "orbit-ir"

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_REASON_TO_RULE: dict[str, dict[str, str]] = {
    "tool-name-mismatch": {
        "id": "orbit-ir/tool-name-mismatch",
        "name": "ToolNameMismatch",
        "short": "Claimed tool name differs from actual tool executed",
        "help": "The transcript records a different tool name than the control plane observed. This indicates the agent misrepresented the tool it called.",
    },
    "argument-digest-mismatch": {
        "id": "orbit-ir/argument-digest-mismatch",
        "name": "ArgumentDigestMismatch",
        "short": "Claimed arguments differ from actual arguments",
        "help": "The SHA-256 digest of the claimed arguments does not match the digest of the actual arguments recorded by the control plane.",
    },
    "agent-id-mismatch": {
        "id": "orbit-ir/agent-id-mismatch",
        "name": "AgentIdentityMismatch",
        "short": "Transcript and control plane disagree on agent identity",
        "help": "The agent_id in the transcript does not match the agent_id in the corresponding control-plane event, suggesting identity confusion or impersonation.",
    },
    "trace-id-mismatch": {
        "id": "orbit-ir/trace-id-mismatch",
        "name": "TraceIdMismatch",
        "short": "Trace IDs do not match between transcript and control plane",
        "help": "The trace_id linking transcript to control-plane events does not match, which may indicate event tampering or logging corruption.",
    },
    "missing-transcript": {
        "id": "orbit-ir/missing-transcript",
        "name": "MissingTranscript",
        "short": "Control-plane event has no corresponding transcript entry",
        "help": "A tool call recorded in the control plane has no matching entry in the transcript, suggesting the agent's own log was suppressed or deleted.",
    },
    "missing-control-plane-event": {
        "id": "orbit-ir/missing-control-plane-event",
        "name": "MissingControlPlaneEvent",
        "short": "Transcript entry has no corresponding control-plane event",
        "help": "A tool call claimed in the transcript has no matching control-plane record, suggesting the execution was never observed or the log was deleted.",
    },
    "unbacked-completion": {
        "id": "orbit-ir/unbacked-completion",
        "name": "UnbackedCompletion",
        "short": "Agent claims task done but independent check failed",
        "help": "The agent reported the task as complete, but the independent verification check for the same tool call did not pass.",
    },
    "oracle-integrity-violation": {
        "id": "orbit-ir/oracle-integrity-violation",
        "name": "OracleIntegrityViolation",
        "short": "Agent modified a protected test expectation",
        "help": "The agent wrote to a resource under the tests/ directory, which contains oracle expectations. Modifying these undermines the integrity of the validation pipeline.",
    },
    "lateral-resource-access": {
        "id": "orbit-ir/lateral-resource-access",
        "name": "LateralResourceAccess",
        "short": "Agent accessed a resource assigned to a different agent",
        "help": "The agent accessed a resource that was explicitly assigned to another agent, indicating unauthorized cross-boundary resource access.",
    },
}

_DEFAULT_RULE = {
    "id": "orbit-ir/unknown",
    "name": "Unknown",
    "short": "Unknown finding reason",
    "help": "A finding reason not yet catalogued.",
}


def findings_to_sarif(
    findings: list[dict],
    *,
    lateral_movement: list[dict] | None = None,
    input_dir: Path | None = None,
) -> dict:
    """Convert orbit-ir findings and lateral-movement detections to SARIF 2.1.0."""
    seen_rules: dict[str, dict] = {}
    results: list[dict] = []

    for item in findings:
        reasons = item.get("reasons", [])
        for reason in reasons:
            rule_meta = _REASON_TO_RULE.get(reason, _DEFAULT_RULE)
            seen_rules[rule_meta["id"]] = rule_meta

        primary_reason = reasons[0] if reasons else "unknown"
        rule_meta = _REASON_TO_RULE.get(primary_reason, _DEFAULT_RULE)

        source_file = item.get("control_source") or item.get("transcript_source") or "unknown"
        source_line = 1
        if item.get("control_line"):
            source_line = _parse_first_line(item["control_line"])
        elif item.get("transcript_line"):
            source_line = _parse_first_line(item["transcript_line"])

        message_parts = []
        if item.get("tool_call_id"):
            message_parts.append(f"tool_call_id={item['tool_call_id']}")
        if item.get("agent_id_transcript"):
            message_parts.append(f"agent={item['agent_id_transcript']}")
        if item.get("claimed_tool") and item.get("actual_tool") and item["claimed_tool"] != item["actual_tool"]:
            message_parts.append(f"claimed={item['claimed_tool']} actual={item['actual_tool']}")
        if item.get("effect"):
            message_parts.append(f"effect={item['effect']}")
        message_text = "; ".join(message_parts) if message_parts else rule_meta["short"]

        mitre = item.get("mitre_techniques", [])
        tags = ["security"]
        for t in mitre:
            tags.append(f"MITRE:{t['id']}")

        result = {
            "ruleId": rule_meta["id"],
            "level": _level_for_reasons(reasons),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": source_file},
                        "region": {"startLine": source_line},
                    }
                }
            ],
            "properties": {
                "finding_id": item.get("finding_id", ""),
                "confidence": item.get("confidence", ""),
                "confidence_score": item.get("confidence_score", 0.0),
                "tags": tags,
            },
        }
        results.append(result)

    for lm in lateral_movement or []:
        rule_meta = _REASON_TO_RULE["lateral-resource-access"]
        seen_rules[rule_meta["id"]] = rule_meta
        message_text = (
            f"agent={lm['agent_id']} accessed {lm['resource']} "
            f"(assigned to {lm['resource_owner']}); effect={lm.get('effect', 'unknown')}"
        )
        result = {
            "ruleId": rule_meta["id"],
            "level": "error",
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "control_plane.jsonl"},
                        "region": {"startLine": lm.get("source_line", 1)},
                    }
                }
            ],
            "properties": {
                "tool_call_id": lm.get("tool_call_id", ""),
                "tags": ["security", "MITRE:T1021"],
            },
        }
        results.append(result)

    rules = []
    for rule_id in sorted(seen_rules):
        meta = seen_rules[rule_id]
        rules.append({
            "id": meta["id"],
            "name": meta["name"],
            "shortDescription": {"text": meta["short"]},
            "fullDescription": {"text": meta["help"]},
            "defaultConfiguration": {"level": "error"},
        })

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": "https://github.com/joeyvictorino/orbit-ir",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def write_sarif(
    findings: list[dict],
    output_path: Path,
    *,
    lateral_movement: list[dict] | None = None,
    input_dir: Path | None = None,
) -> None:
    """Write SARIF to a file."""
    sarif = findings_to_sarif(
        findings,
        lateral_movement=lateral_movement,
        input_dir=input_dir,
    )
    output_path.write_text(
        json.dumps(sarif, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parse_first_line(value: str | int | list | None) -> int:
    if value is None:
        return 1
    if isinstance(value, int):
        return max(value, 1)
    if isinstance(value, list):
        return max(int(value[0]), 1) if value else 1
    first = str(value).split(";")[0].strip()
    try:
        return max(int(first), 1)
    except (ValueError, TypeError):
        return 1


def _level_for_reasons(reasons: list[str]) -> str:
    """Map the most severe reason to a SARIF level."""
    severity_order = ["error", "warning", "note"]
    best = "note"
    for reason in reasons:
        rule_meta = _REASON_TO_RULE.get(reason)
        if rule_meta:
            level = _SEVERITY_TO_SARIF.get("high", "error")
        else:
            level = "warning"
        if severity_order.index(level) < severity_order.index(best):
            best = level
    return best
