"""Downsample large evidence datasets for testing and exploration.

Supports count-based, percentage-based, and stratified sampling
by agent ID or evidence source file.
"""
from __future__ import annotations

import json
import random
from pathlib import Path


def sample_evidence(
    evidence_dir: Path,
    output_dir: Path,
    *,
    count: int | None = None,
    percent: float | None = None,
    stratify_by: str | None = None,
    seed: int = 42,
) -> dict:
    evidence_dir = Path(evidence_dir)
    output_dir = Path(output_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    result: dict[str, dict] = {}
    source_files = sorted(evidence_dir.glob("*.jsonl"))

    for src in source_files:
        rows = _read_jsonl(src)
        if not rows:
            result[src.name] = {"input": 0, "output": 0}
            _write_jsonl(output_dir / src.name, [])
            continue

        if stratify_by:
            sampled = _stratified_sample(rows, stratify_by, count, percent, rng)
        elif count is not None:
            n = min(count, len(rows))
            sampled = rng.sample(rows, n)
        elif percent is not None:
            p = max(0.0, min(100.0, percent))
            n = max(1, int(len(rows) * p / 100.0))
            sampled = rng.sample(rows, min(n, len(rows)))
        else:
            sampled = rows

        sampled.sort(key=lambda r: r.get("timestamp", r.get("event_id", "")))
        _write_jsonl(output_dir / src.name, sampled)
        result[src.name] = {"input": len(rows), "output": len(sampled)}

    total_in = sum(v["input"] for v in result.values())
    total_out = sum(v["output"] for v in result.values())
    return {
        "files": result,
        "total_input": total_in,
        "total_output": total_out,
        "reduction_percent": round((1 - total_out / total_in) * 100, 1) if total_in else 0.0,
        "seed": seed,
    }


def _stratified_sample(
    rows: list[dict],
    key: str,
    count: int | None,
    percent: float | None,
    rng: random.Random,
) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        val = str(row.get(key, "_unknown"))
        groups.setdefault(val, []).append(row)

    sampled: list[dict] = []
    for group_rows in groups.values():
        if count is not None:
            per_group = max(1, count // len(groups))
            n = min(per_group, len(group_rows))
        elif percent is not None:
            p = max(0.0, min(100.0, percent))
            n = max(1, int(len(group_rows) * p / 100.0))
        else:
            n = len(group_rows)
        sampled.extend(rng.sample(group_rows, min(n, len(group_rows))))

    return sampled


def format_sample_text(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"Sample: {result['total_input']} -> {result['total_output']} events "
                 f"({result['reduction_percent']}% reduction, seed={result['seed']})")
    lines.append("")
    for fname, info in sorted(result["files"].items()):
        lines.append(f"  {fname}: {info['input']} -> {info['output']}")
    return "\n".join(lines) + "\n"


def _read_jsonl(path: Path) -> list[dict]:
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


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
