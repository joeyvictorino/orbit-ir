"""Convert evidence between JSONL and CSV formats."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path


def _flatten(obj: dict, prefix: str = "") -> dict:
    """Flatten nested dict with dot-notation keys."""
    out: dict = {}
    for k, v in obj.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def _unflatten(flat: dict) -> dict:
    """Unflatten dot-notation keys back into nested dicts."""
    out: dict = {}
    for k, v in flat.items():
        parts = k.split(".")
        d = out
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        val = v
        if isinstance(val, str):
            if val == "":
                val = None
            elif val.lower() == "true":
                val = True
            elif val.lower() == "false":
                val = False
            else:
                try:
                    val = int(val)
                except ValueError:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
        d[parts[-1]] = val
    return out


def convert_jsonl_to_csv(input_path: Path, output_path: Path) -> dict:
    """Convert a JSONL file to CSV with flattened fields."""
    rows: list[dict] = []
    with input_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(_flatten(json.loads(line)))

    if not rows:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")
        return {"rows": 0, "columns": 0, "input": str(input_path), "output": str(output_path)}

    all_keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for k in row:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if row.get(k) is None else row.get(k, "")) for k in all_keys})

    return {
        "rows": len(rows),
        "columns": len(all_keys),
        "input": str(input_path),
        "output": str(output_path),
    }


def convert_csv_to_jsonl(input_path: Path, output_path: Path) -> dict:
    """Convert a CSV file to JSONL, unflattening dot-notation keys."""
    with input_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for row in rows:
            obj = _unflatten(row)
            f.write(json.dumps(obj, sort_keys=True) + "\n")

    return {
        "rows": len(rows),
        "input": str(input_path),
        "output": str(output_path),
    }


EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")


def convert_evidence_dir(input_dir: Path, output_dir: Path, target_format: str) -> dict:
    """Convert all evidence files in a directory."""
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Not a directory: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    total_rows = 0

    if target_format == "csv":
        for name in EVIDENCE_FILES:
            src = input_dir / name
            if src.exists():
                dst = output_dir / name.replace(".jsonl", ".csv")
                r = convert_jsonl_to_csv(src, dst)
                total_rows += r["rows"]
                results.append(r)
    elif target_format == "jsonl":
        for name in ("messages.csv", "transcripts.csv", "control_plane.csv"):
            src = input_dir / name
            if src.exists():
                dst = output_dir / name.replace(".csv", ".jsonl")
                r = convert_csv_to_jsonl(src, dst)
                total_rows += r["rows"]
                results.append(r)
    else:
        raise ValueError(f"Unsupported target format: {target_format}")

    return {
        "files_converted": len(results),
        "total_rows": total_rows,
        "target_format": target_format,
        "details": results,
    }


def format_convert_text(result: dict) -> str:
    """Format conversion result as human-readable text."""
    lines: list[str] = []
    if "files_converted" in result:
        lines.append(f"Converted {result['files_converted']} file(s) to {result['target_format']}")
        lines.append(f"Total rows: {result['total_rows']}")
        for d in result.get("details", []):
            lines.append(f"  {d['input']} -> {d['output']} ({d['rows']} rows)")
    else:
        lines.append(f"Converted: {result['input']} -> {result['output']}")
        lines.append(f"Rows: {result['rows']}")
        if "columns" in result:
            lines.append(f"Columns: {result['columns']}")
    return "\n".join(lines) + "\n"
