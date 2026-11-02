"""Strip PII from evidence JSONL files with typed placeholders."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("PHONE", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("API_KEY", re.compile(r"\b[a-zA-Z0-9_]{32,}\b")),
]


def load_patterns(pattern_file: Path | None = None) -> list[tuple[str, re.Pattern[str]]]:
    patterns = list(BUILTIN_PATTERNS)
    if pattern_file is not None and pattern_file.exists():
        for line in pattern_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                name, regex = line.split(":", 1)
                patterns.append((name.strip(), re.compile(regex.strip())))
    return patterns


def _replace_in_value(
    value: str,
    patterns: list[tuple[str, re.Pattern[str]]],
    seen: dict[str, str],
) -> tuple[str, list[dict[str, Any]]]:
    redactions: list[dict[str, Any]] = []
    result = value
    for label, regex in patterns:
        for match in regex.finditer(value):
            original = match.group()
            placeholder = f"[{label}]"
            if original not in seen:
                seen[original] = placeholder
            if original in result:
                result = result.replace(original, seen[original])
                redactions.append({"type": label, "original": original, "replacement": seen[original]})
    return result, redactions


def _redact_obj(
    obj: dict[str, Any],
    patterns: list[tuple[str, re.Pattern[str]]],
    seen: dict[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    all_redactions: list[dict[str, Any]] = []
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if isinstance(v, str):
            replaced, reds = _replace_in_value(v, patterns, seen)
            out[k] = replaced
            all_redactions.extend(reds)
        elif isinstance(v, dict):
            nested, reds = _redact_obj(v, patterns, seen)
            out[k] = nested
            all_redactions.extend(reds)
        elif isinstance(v, list):
            new_list: list[Any] = []
            for item in v:
                if isinstance(item, str):
                    replaced, reds = _replace_in_value(item, patterns, seen)
                    new_list.append(replaced)
                    all_redactions.extend(reds)
                elif isinstance(item, dict):
                    nested, reds = _redact_obj(item, patterns, seen)
                    new_list.append(nested)
                    all_redactions.extend(reds)
                else:
                    new_list.append(item)
            out[k] = new_list
        else:
            out[k] = v
    return out, all_redactions


def redact_evidence(
    input_path: Path,
    output_path: Path,
    *,
    pattern_file: Path | None = None,
    patterns: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    if not input_path.is_dir():
        raise FileNotFoundError(f"{input_path} is not a directory")

    all_patterns = load_patterns(pattern_file)
    if patterns is not None:
        name_set = {p.upper() for p in patterns}
        all_patterns = [(n, r) for n, r in all_patterns if n in name_set]

    seen: dict[str, str] = {}
    files = sorted(input_path.glob("*.jsonl"))
    total_events = 0
    total_redactions = 0
    redactions_by_type: dict[str, int] = {}
    details: list[dict[str, Any]] = []

    for fpath in files:
        lines = fpath.read_text().splitlines()
        redacted_lines: list[str] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            total_events += 1
            new_obj, reds = _redact_obj(obj, all_patterns, seen)
            total_redactions += len(reds)
            for r in reds:
                rtype = r["type"]
                redactions_by_type[rtype] = redactions_by_type.get(rtype, 0) + 1
            details.extend(reds)
            redacted_lines.append(json.dumps(new_obj, sort_keys=True))

        if not dry_run:
            output_path.mkdir(parents=True, exist_ok=True)
            out_file = output_path / fpath.name
            out_file.write_text("\n".join(redacted_lines) + "\n")

    return {
        "files": len(files),
        "events": total_events,
        "redactions": total_redactions,
        "redactions_by_type": redactions_by_type,
        "details": details[:100],
        "dry_run": dry_run,
    }


def format_redact_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    mode = "DRY RUN" if result.get("dry_run") else "PII Redaction Results:"
    lines.append(mode)
    lines.append(f"  Files processed:  {result['files']}")
    lines.append(f"  Events scanned:   {result['events']}")
    lines.append(f"  Total redactions: {result['redactions']}")
    if result.get("redactions_by_type"):
        lines.append("")
        lines.append("  By type:")
        for name, count in sorted(result["redactions_by_type"].items()):
            lines.append(f"    {name}: {count}")
    if result.get("details"):
        lines.append("")
        shown = result["details"][:20]
        for d in shown:
            lines.append(f"  {d['type']}: {d['original']} -> {d['replacement']}")
        if len(result["details"]) > 20:
            lines.append(f"  ... and {len(result['details']) - 20} more")
    lines.append("")
    return "\n".join(lines)
