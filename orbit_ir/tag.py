"""Tag evidence events with custom labels based on matching rules."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")


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


def _matches_rule(event: dict, rule: dict) -> bool:
    """Check if an event matches a tagging rule."""
    tag_key = "tag"
    for key, value in rule.items():
        if key == tag_key:
            continue
        if key == "after":
            ts = event.get("timestamp", "")
            if not ts or ts <= value:
                return False
        elif key == "before":
            ts = event.get("timestamp", "")
            if not ts or ts >= value:
                return False
        elif key == "tool":
            claimed = event.get("claimed_tool", "")
            actual = event.get("actual_tool", "")
            tool_field = event.get("tool", "")
            if value not in (claimed, actual, tool_field):
                return False
        else:
            if event.get(key) != value:
                return False
    return True


def tag_events(
    input_dir: Path,
    output_dir: Path,
    rules: list[dict],
) -> dict:
    """Apply tagging rules to evidence events and write tagged files to output_dir.

    Each rule is a dict like {"agent_id": "a1", "tag": "suspicious"}.
    Events matching the rule get the tag added to their "tags" list.
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    tags_applied: Counter[str] = Counter()
    file_results: list[dict] = []

    for fname in EVIDENCE_FILES:
        rows = _load_jsonl(input_dir / fname)
        if not rows:
            continue

        file_tagged = 0
        for row in rows:
            for rule in rules:
                tag = rule.get("tag", "")
                if not tag:
                    continue
                if _matches_rule(row, rule):
                    existing = row.get("tags", [])
                    if tag not in existing:
                        existing.append(tag)
                        row["tags"] = existing
                        tags_applied[tag] += 1
                        file_tagged += 1

        _write_jsonl(output_dir / fname, rows)
        file_results.append({"file": fname, "rows": len(rows), "tagged": file_tagged})

    # Copy ground_truth.json if present.
    gt = input_dir / "ground_truth.json"
    if gt.exists():
        (output_dir / "ground_truth.json").write_text(
            gt.read_text(encoding="utf-8"), encoding="utf-8"
        )

    return {
        "files": file_results,
        "tags_applied": dict(tags_applied),
        "total_tagged": sum(tags_applied.values()),
        "rules_count": len(rules),
    }


def list_tags(evidence_dir: Path) -> dict:
    """Summarize all tags present in evidence files."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    tag_counts: Counter[str] = Counter()
    tags_by_file: dict[str, Counter[str]] = {}

    for fname in EVIDENCE_FILES:
        rows = _load_jsonl(evidence_dir / fname)
        file_counter: Counter[str] = Counter()
        for row in rows:
            for tag in row.get("tags", []):
                tag_counts[tag] += 1
                file_counter[tag] += 1
        if file_counter:
            tags_by_file[fname] = file_counter

    return {
        "total_tags": dict(tag_counts),
        "by_file": {k: dict(v) for k, v in tags_by_file.items()},
        "unique_tags": sorted(tag_counts.keys()),
    }


def filter_by_tag(evidence_dir: Path, tag: str) -> list[dict]:
    """Return only events that carry the given tag."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    results: list[dict] = []
    for fname in EVIDENCE_FILES:
        rows = _load_jsonl(evidence_dir / fname)
        for row in rows:
            if tag in row.get("tags", []):
                row["_source_file"] = fname
                results.append(row)
    return results


def format_tag_text(result: dict) -> str:
    """Human-readable tagging summary."""
    lines = [
        f"Rules applied: {result['rules_count']}",
        f"Total events tagged: {result['total_tagged']}",
    ]
    if result["tags_applied"]:
        lines.append("Tags:")
        for tag, count in sorted(result["tags_applied"].items()):
            lines.append(f"  {tag}: {count}")
    for fr in result["files"]:
        lines.append(f"  {fr['file']}: {fr['rows']} rows, {fr['tagged']} tagged")
    return "\n".join(lines) + "\n"
