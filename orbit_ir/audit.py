"""Reproducibility audit for evidence datasets.

Hashes each evidence file, verifies completeness, and cross-checks
agent references across sources.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")
OPTIONAL_FILES = ("ground_truth.json",)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def audit_evidence(input_dir: Path) -> dict:
    """Run a reproducibility audit on the evidence in *input_dir*.

    Returns a JSON-serialisable report with file hashes, row counts,
    cross-reference checks, and an overall pass/fail verdict.
    """
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    files: list[dict] = []
    checks: list[dict] = []
    passed = True

    for name in EVIDENCE_FILES:
        path = input_dir / name
        if not path.exists():
            files.append({
                "name": name,
                "present": False,
                "sha256": None,
                "bytes": 0,
                "rows": 0,
            })
            passed = False
            checks.append({
                "check": f"{name}_exists",
                "passed": False,
                "detail": f"{name} is missing",
            })
            continue

        size = path.stat().st_size
        sha = _sha256(path)
        rows = _read_jsonl(path)
        files.append({
            "name": name,
            "present": True,
            "sha256": sha,
            "bytes": size,
            "rows": len(rows),
        })
        checks.append({
            "check": f"{name}_exists",
            "passed": True,
            "detail": f"{name} present ({len(rows)} rows, {size} bytes)",
        })

        if size == 0:
            checks.append({
                "check": f"{name}_nonempty",
                "passed": False,
                "detail": f"{name} is empty",
            })
            passed = False
        else:
            checks.append({
                "check": f"{name}_nonempty",
                "passed": True,
                "detail": f"{name} has {len(rows)} rows",
            })

    for name in OPTIONAL_FILES:
        path = input_dir / name
        if path.exists():
            sha = _sha256(path)
            size = path.stat().st_size
            files.append({
                "name": name,
                "present": True,
                "sha256": sha,
                "bytes": size,
                "rows": None,
            })
        else:
            files.append({
                "name": name,
                "present": False,
                "sha256": None,
                "bytes": 0,
                "rows": None,
            })

    messages = _read_jsonl(input_dir / "messages.jsonl")
    transcripts = _read_jsonl(input_dir / "transcripts.jsonl")
    control = _read_jsonl(input_dir / "control_plane.jsonl")

    msg_agents: set[str] = set()
    for row in messages:
        if "agent_id" in row:
            msg_agents.add(row["agent_id"])
        if row.get("recipient_agent_id"):
            msg_agents.add(row["recipient_agent_id"])

    tx_agents: set[str] = set()
    for row in transcripts:
        if "agent_id" in row:
            tx_agents.add(row["agent_id"])

    cp_agents: set[str] = set()
    for row in control:
        if "agent_id" in row:
            cp_agents.add(row["agent_id"])

    all_agents = msg_agents | tx_agents | cp_agents

    if messages and transcripts:
        tx_only = tx_agents - msg_agents
        if tx_only:
            checks.append({
                "check": "transcript_agents_in_messages",
                "passed": False,
                "detail": f"{len(tx_only)} transcript agent(s) not in messages: {sorted(tx_only)[:5]}",
            })
            passed = False
        else:
            checks.append({
                "check": "transcript_agents_in_messages",
                "passed": True,
                "detail": "all transcript agents appear in messages",
            })

    if messages and control:
        cp_only = cp_agents - msg_agents
        if cp_only:
            checks.append({
                "check": "control_plane_agents_in_messages",
                "passed": False,
                "detail": f"{len(cp_only)} control-plane agent(s) not in messages: {sorted(cp_only)[:5]}",
            })
            passed = False
        else:
            checks.append({
                "check": "control_plane_agents_in_messages",
                "passed": True,
                "detail": "all control-plane agents appear in messages",
            })

    msg_ids: list[str] = [r.get("event_id", "") for r in messages if r.get("event_id")]
    if msg_ids and len(msg_ids) != len(set(msg_ids)):
        dup_count = len(msg_ids) - len(set(msg_ids))
        checks.append({
            "check": "message_ids_unique",
            "passed": False,
            "detail": f"{dup_count} duplicate event_id(s) in messages",
        })
        passed = False
    elif msg_ids:
        checks.append({
            "check": "message_ids_unique",
            "passed": True,
            "detail": f"all {len(msg_ids)} message event_ids are unique",
        })

    return {
        "directory": str(input_dir),
        "passed": passed,
        "files": files,
        "checks": checks,
        "agents": len(all_agents),
        "total_rows": sum(f["rows"] for f in files if f["rows"] is not None),
    }


def format_audit_text(report: dict) -> str:
    """Human-readable audit report."""
    verdict = "PASS" if report["passed"] else "FAIL"
    lines = [
        f"Audit: {report['directory']}",
        f"  Verdict: {verdict}",
        f"  Agents:  {report['agents']}",
        f"  Rows:    {report['total_rows']}",
        "",
        "  Files:",
    ]
    for f in report["files"]:
        if f["present"]:
            rows_str = f"  {f['rows']} rows" if f["rows"] is not None else ""
            lines.append(f"    [OK]   {f['name']}: sha256={f['sha256'][:16]}...{rows_str}")
        else:
            lines.append(f"    [MISS] {f['name']}")

    lines.append("")
    lines.append("  Checks:")
    for c in report["checks"]:
        mark = "PASS" if c["passed"] else "FAIL"
        lines.append(f"    [{mark}] {c['check']}: {c['detail']}")

    return "\n".join(lines) + "\n"
