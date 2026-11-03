"""Export findings to various formats without re-running analysis.

Reads an existing findings.json and converts to CSV, CEF, or SARIF.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .cef import findings_to_cef
from .sarif import findings_to_sarif


_CSV_FIELDS = (
    "finding_id", "tool_call_id", "agent_id_transcript", "agent_id_control",
    "trace_id_transcript", "trace_id_control", "reasons", "mitre_techniques",
    "transcript_source", "transcript_line", "control_source", "control_line",
    "claimed_tool", "actual_tool", "effect", "confidence", "confidence_score",
)


def findings_to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for item in findings:
        row = dict(item)
        row["reasons"] = ";".join(row.get("reasons", []))
        row["mitre_techniques"] = ";".join(
            f"{t['id']}:{t['name']}" for t in row.get("mitre_techniques", [])
        )
        writer.writerow({key: row.get(key) for key in _CSV_FIELDS})
    return buf.getvalue()


def export_findings(
    findings_path: Path,
    fmt: str,
    *,
    output_path: Path | None = None,
) -> str:
    findings = json.loads(findings_path.read_text(encoding="utf-8"))

    if fmt == "csv":
        text = findings_to_csv(findings)
    elif fmt == "cef":
        text = findings_to_cef(findings)
    elif fmt == "sarif":
        sarif = findings_to_sarif(findings)
        text = json.dumps(sarif, indent=2, sort_keys=True) + "\n"
    elif fmt == "json":
        text = json.dumps(findings, indent=2, sort_keys=True) + "\n"
    else:
        raise ValueError(f"unsupported export format: {fmt}")

    if output_path is not None:
        output_path.write_text(text, encoding="utf-8")

    return text
