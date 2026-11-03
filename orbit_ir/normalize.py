"""Normalize evidence fields: timestamps, agent IDs, whitespace, custom renames."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")

_MULTI_WS = re.compile(r"\s{2,}")


def _parse_timestamp(value: str) -> str | None:
    """Attempt to parse a timestamp string into ISO 8601 UTC."""
    if not value:
        return None

    # Unix epoch (integer or float as string).
    try:
        epoch = float(value)
        if epoch > 1e12:
            epoch /= 1000  # milliseconds
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        pass

    # Already ISO 8601 with Z suffix — pass through.
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return None


def _normalize_row(row: dict, renames: dict[str, str] | None) -> tuple[dict, int]:
    """Normalize a single evidence row. Returns (new_row, change_count)."""
    changes = 0
    out = dict(row)

    # Apply field renames.
    if renames:
        for old_name, new_name in renames.items():
            if old_name in out and new_name not in out:
                out[new_name] = out.pop(old_name)
                changes += 1

    # Normalize timestamp to ISO 8601 UTC.
    if "timestamp" in out and out["timestamp"]:
        normalized = _parse_timestamp(str(out["timestamp"]))
        if normalized and normalized != out["timestamp"]:
            out["timestamp"] = normalized
            changes += 1

    # Lowercase agent_id fields.
    for key in ("agent_id", "recipient_agent_id"):
        if key in out and isinstance(out[key], str) and out[key] != out[key].lower():
            out[key] = out[key].lower()
            changes += 1

    # Collapse duplicate whitespace in string fields.
    for key, val in list(out.items()):
        if isinstance(val, str) and _MULTI_WS.search(val):
            out[key] = _MULTI_WS.sub(" ", val).strip()
            changes += 1

    return out, changes


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def normalize_evidence(
    input_dir: Path,
    output_dir: Path,
    renames: dict[str, str] | None = None,
) -> dict:
    """Normalize all evidence files and write to output_dir."""
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    file_results: list[dict] = []
    total_changes = 0

    for fname in EVIDENCE_FILES:
        src = input_dir / fname
        rows = _load_jsonl(src)
        if not rows:
            continue

        normalized: list[dict] = []
        file_changes = 0
        for row in rows:
            new_row, changes = _normalize_row(row, renames)
            normalized.append(new_row)
            file_changes += changes

        _write_jsonl(output_dir / fname, normalized)
        file_results.append({
            "file": fname,
            "rows": len(normalized),
            "changes": file_changes,
        })
        total_changes += file_changes

    # Copy ground_truth.json if present.
    gt = input_dir / "ground_truth.json"
    if gt.exists():
        (output_dir / "ground_truth.json").write_text(
            gt.read_text(encoding="utf-8"), encoding="utf-8"
        )

    return {
        "files": file_results,
        "total_changes": total_changes,
        "renames_applied": list(renames.keys()) if renames else [],
    }


def format_normalize_text(result: dict) -> str:
    """Human-readable normalization summary."""
    lines = [f"Total changes: {result['total_changes']}"]
    if result["renames_applied"]:
        lines.append(f"Renames: {', '.join(result['renames_applied'])}")
    for fr in result["files"]:
        lines.append(f"  {fr['file']}: {fr['rows']} rows, {fr['changes']} changes")
    return "\n".join(lines) + "\n"
