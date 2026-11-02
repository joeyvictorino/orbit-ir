"""CEF (Common Event Format) export for orbit-ir findings.

Produces ArcSight Common Event Format lines for SIEM ingestion
(Splunk, ArcSight, QRadar, ELK).

Format:
    CEF:0|ORBIT|AgentIR|1.0|<signatureId>|<name>|<severity>|<extensions>
"""

from __future__ import annotations


_SEVERITY_MAP: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 3,
    "info": 1,
}

_REASON_TITLES: dict[str, str] = {
    "tool-name-mismatch": "Claimed tool name differs from actual tool executed",
    "argument-digest-mismatch": "Claimed arguments differ from actual arguments",
    "agent-id-mismatch": "Transcript and control plane disagree on agent identity",
    "trace-id-mismatch": "Trace IDs do not match between transcript and control plane",
    "missing-transcript": "Control-plane event has no corresponding transcript entry",
    "missing-control-plane-event": "Transcript entry has no corresponding control-plane event",
    "unbacked-completion": "Agent claims task done but independent check failed",
    "oracle-integrity-violation": "Agent modified a protected test expectation",
    "lateral-resource-access": "Agent accessed a resource assigned to a different agent",
}


def _escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_ext_value(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _severity_int(finding: dict) -> int:
    severity = finding.get("severity", "medium")
    if isinstance(severity, str):
        return _SEVERITY_MAP.get(severity.lower(), 5)
    return 5


def _build_extensions(finding: dict) -> str:
    parts: list[str] = []

    agent = finding.get("agent_id_transcript") or finding.get("agent_id") or ""
    if agent:
        parts.append(f"src={_escape_ext_value(agent)}")

    reasons = finding.get("reasons", [])
    detection_type = reasons[0] if reasons else "unknown"
    parts.append(f"cs1={_escape_ext_value(detection_type)}")
    parts.append("cs1Label=DetectionType")

    source_file = finding.get("control_source") or finding.get("transcript_source") or ""
    source_line = finding.get("control_line") or finding.get("transcript_line") or ""
    if isinstance(source_line, list):
        source_line = source_line[0] if source_line else ""
    evidence_ref = f"{source_file}:{source_line}" if source_file else ""
    if evidence_ref:
        parts.append(f"cs2={_escape_ext_value(evidence_ref)}")
        parts.append("cs2Label=EvidenceRef")

    evidence_hash = finding.get("evidence_hash") or finding.get("finding_id") or ""
    if evidence_hash:
        parts.append(f"cs3={_escape_ext_value(str(evidence_hash))}")
        parts.append("cs3Label=EvidenceHash")

    msg_parts: list[str] = []
    if finding.get("tool_call_id"):
        msg_parts.append(f"tool_call_id={finding['tool_call_id']}")
    if finding.get("claimed_tool") and finding.get("actual_tool") and finding["claimed_tool"] != finding["actual_tool"]:
        msg_parts.append(f"claimed={finding['claimed_tool']} actual={finding['actual_tool']}")
    if finding.get("effect"):
        msg_parts.append(f"effect={finding['effect']}")
    if msg_parts:
        parts.append(f"msg={_escape_ext_value('; '.join(msg_parts))}")

    return " ".join(parts)


def finding_to_cef(finding: dict) -> str:
    reasons = finding.get("reasons", [])
    signature_id = reasons[0] if reasons else "unknown"
    name = _REASON_TITLES.get(signature_id, signature_id)
    severity = _severity_int(finding)
    extensions = _build_extensions(finding)

    header = "|".join([
        "CEF:0",
        _escape_header("ORBIT"),
        _escape_header("AgentIR"),
        _escape_header("1.0"),
        _escape_header(signature_id),
        _escape_header(name),
        str(severity),
    ])
    return f"{header}|{extensions}"


def findings_to_cef(findings: list[dict]) -> str:
    lines = [finding_to_cef(f) for f in findings]
    return "\n".join(lines) + "\n" if lines else ""
