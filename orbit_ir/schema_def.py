"""Evidence file schema definitions and validation."""

from __future__ import annotations

import json
from pathlib import Path


EVIDENCE_SCHEMAS: dict[str, dict[str, dict]] = {
    "messages.jsonl": {
        "event_id": {"required": True, "type": "str"},
        "timestamp": {"required": True, "type": "str"},
        "agent_id": {"required": True, "type": "str"},
        "recipient_agent_id": {"required": False, "type": "str"},
        "content": {"required": False, "type": "str"},
    },
    "transcripts.jsonl": {
        "call_id": {"required": True, "type": "str"},
        "agent_id": {"required": True, "type": "str"},
        "claimed_tool": {"required": True, "type": "str"},
        "actual_tool": {"required": True, "type": "str"},
        "timestamp": {"required": False, "type": "str"},
    },
    "control_plane.jsonl": {
        "event_id": {"required": True, "type": "str"},
        "agent_id": {"required": True, "type": "str"},
        "tool": {"required": True, "type": "str"},
        "timestamp": {"required": False, "type": "str"},
    },
}


def validate_evidence_schema(
    evidence_dir: Path, *, strict: bool = False
) -> list[dict]:
    """Validate evidence files against expected schemas.

    Returns a list of issues. Each issue has: file, line (1-based or 0 for
    file-level), severity ('error' or 'warning'), and message.
    """
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"Not a directory: {evidence_dir}")

    issues: list[dict] = []

    for filename, field_defs in EVIDENCE_SCHEMAS.items():
        path = evidence_dir / filename
        if not path.exists():
            issues.append({
                "file": filename,
                "line": 0,
                "severity": "warning",
                "message": f"File not found: {filename}",
            })
            continue

        required_fields = {k for k, v in field_defs.items() if v["required"]}
        known_fields = set(field_defs.keys())

        with path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as e:
                    issues.append({
                        "file": filename,
                        "line": lineno,
                        "severity": "error",
                        "message": f"Invalid JSON: {e}",
                    })
                    continue

                if not isinstance(row, dict):
                    issues.append({
                        "file": filename,
                        "line": lineno,
                        "severity": "error",
                        "message": "Row is not a JSON object",
                    })
                    continue

                for field in required_fields:
                    if field not in row:
                        issues.append({
                            "file": filename,
                            "line": lineno,
                            "severity": "error",
                            "message": f"Missing required field: {field}",
                        })

                for field in row:
                    if field not in known_fields:
                        sev = "error" if strict else "warning"
                        issues.append({
                            "file": filename,
                            "line": lineno,
                            "severity": sev,
                            "message": f"Unknown field: {field}",
                        })

    return issues


def format_schema_text() -> str:
    """Format evidence schemas as human-readable documentation."""
    lines: list[str] = ["Evidence File Schemas", "=" * 40, ""]
    for filename, fields in EVIDENCE_SCHEMAS.items():
        lines.append(f"  {filename}")
        lines.append(f"  {'-' * len(filename)}")
        for field_name, spec in fields.items():
            req = "required" if spec["required"] else "optional"
            lines.append(f"    {field_name}: {spec['type']} ({req})")
        lines.append("")
    return "\n".join(lines)


def format_validation_text(issues: list[dict]) -> str:
    """Format validation issues as human-readable text."""
    if not issues:
        return "Validation passed: no issues found.\n"

    lines: list[str] = []
    errors = [i for i in issues if i["severity"] == "error"]
    warnings = [i for i in issues if i["severity"] == "warning"]

    for issue in issues:
        sev = issue["severity"].upper()
        loc = f"{issue['file']}:{issue['line']}" if issue["line"] else issue["file"]
        lines.append(f"  [{sev}] {loc}: {issue['message']}")

    lines.append("")
    lines.append(f"  {len(errors)} error(s), {len(warnings)} warning(s)")
    return "\n".join(lines) + "\n"
