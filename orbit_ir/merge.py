"""Merge multiple orbit-ir evidence directories into one."""

from __future__ import annotations

import json
from pathlib import Path


_JSONL_FILES = {
    "messages.jsonl": "event_id",
    "transcripts.jsonl": "call_id",
    "control_plane.jsonl": "event_id",
}


def merge_evidence(input_dirs: list[Path], output_dir: Path) -> dict:
    """Merge evidence from multiple directories, deduplicating by primary key.

    Returns a summary dict with per-file counts and duplicate stats.
    """
    for d in input_dirs:
        if not d.is_dir():
            raise FileNotFoundError(f"Evidence directory not found: {d}")

    output_dir.mkdir(parents=True, exist_ok=True)

    summary: dict = {
        "input_dirs": [str(d) for d in input_dirs],
        "output_dir": str(output_dir),
        "files": {},
    }

    for filename, pk in _JSONL_FILES.items():
        records, total, dupes = _merge_jsonl(input_dirs, filename, pk)
        out_path = output_dir / filename
        _write_jsonl(out_path, records)
        summary["files"][filename] = {
            "total_input_records": total,
            "duplicates_removed": dupes,
            "output_records": len(records),
        }

    gt_result = _merge_ground_truth(input_dirs, output_dir)
    summary["ground_truth"] = gt_result

    return summary


def _merge_jsonl(
    dirs: list[Path], filename: str, pk: str
) -> tuple[list[dict], int, int]:
    """Read and deduplicate JSONL records across directories."""
    seen: dict[str, dict] = {}
    total = 0
    for d in dirs:
        path = d / filename
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                record = json.loads(line)
                key = record.get(pk, "")
                if key and key not in seen:
                    seen[key] = record

    records = list(seen.values())
    if filename == "messages.jsonl":
        records.sort(key=lambda r: r.get("timestamp", ""))
    return records, total, total - len(records)


def _merge_ground_truth(dirs: list[Path], output_dir: Path) -> dict:
    """Merge ground_truth.json files (union of top-level keys)."""
    merged: dict = {}
    conflicts: list[str] = []
    found = False
    for d in dirs:
        gt_path = d / "ground_truth.json"
        if not gt_path.exists():
            continue
        found = True
        data = json.loads(gt_path.read_text(encoding="utf-8"))
        for k, v in data.items():
            if k in merged and merged[k] != v:
                conflicts.append(k)
            merged[k] = v

    result: dict = {"found": found, "conflicts": conflicts}
    if found:
        (output_dir / "ground_truth.json").write_text(
            json.dumps(merged, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result["keys"] = len(merged)
    return result


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
