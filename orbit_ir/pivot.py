"""Cross-field frequency analysis (pivot table) for evidence events."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _resolve_field(event: dict[str, Any], field: str) -> str:
    parts = field.split(".")
    current: Any = event
    for p in parts:
        if isinstance(current, dict) and p in current:
            current = current[p]
        else:
            return "(empty)"
    return str(current) if current is not None else "(empty)"


def pivot_events(
    path: Path,
    row_field: str,
    col_field: str,
) -> dict[str, Any]:
    events = load_events(path)
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    row_totals: dict[str, int] = defaultdict(int)
    col_totals: dict[str, int] = defaultdict(int)

    for ev in events:
        row_val = _resolve_field(ev, row_field)
        col_val = _resolve_field(ev, col_field)
        matrix[row_val][col_val] += 1
        row_totals[row_val] += 1
        col_totals[col_val] += 1

    rows = sorted(matrix.keys())
    cols = sorted(col_totals.keys())

    cells: list[dict[str, Any]] = []
    for r in rows:
        for c in cols:
            count = matrix[r].get(c, 0)
            if count > 0:
                cells.append({"row": r, "col": c, "count": count})

    return {
        "row_field": row_field,
        "col_field": col_field,
        "total_events": len(events),
        "rows": rows,
        "cols": cols,
        "cells": cells,
        "row_totals": dict(row_totals),
        "col_totals": dict(col_totals),
    }


def format_pivot_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Pivot: {result['row_field']} x {result['col_field']}")
    lines.append(f"Total events: {result['total_events']}\n")

    cols = result["cols"]
    rows = result["rows"]

    cell_map: dict[tuple[str, str], int] = {}
    for c in result["cells"]:
        cell_map[(c["row"], c["col"])] = c["count"]

    col_width = max((len(c) for c in cols), default=6)
    col_width = max(col_width, 6)
    row_width = max((len(r) for r in rows), default=10)
    row_width = max(row_width, 10)

    header = " " * (row_width + 2)
    for c in cols:
        header += f"{c:>{col_width}}  "
    header += f"{'Total':>{col_width}}"
    lines.append(header)
    lines.append("-" * len(header))

    for r in rows:
        line = f"{r:<{row_width}}  "
        for c in cols:
            count = cell_map.get((r, c), 0)
            line += f"{count:>{col_width}}  "
        line += f"{result['row_totals'].get(r, 0):>{col_width}}"
        lines.append(line)

    footer = f"{'Total':<{row_width}}  "
    for c in cols:
        footer += f"{result['col_totals'].get(c, 0):>{col_width}}  "
    footer += f"{result['total_events']:>{col_width}}"
    lines.append("-" * len(header))
    lines.append(footer)
    lines.append("")
    return "\n".join(lines)
