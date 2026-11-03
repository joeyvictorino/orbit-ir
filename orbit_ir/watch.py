"""Monitor an evidence directory for changes and re-analyze."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from .stats import evidence_stats

EVIDENCE_FILES = ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl")


def snapshot_evidence(evidence_dir: Path) -> dict:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    files: dict[str, dict] = {}
    for name in EVIDENCE_FILES:
        path = evidence_dir / name
        if path.exists():
            stat = path.stat()
            line_count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            files[name] = {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "lines": line_count,
            }
        else:
            files[name] = {"size": 0, "mtime": 0, "lines": 0, "missing": True}

    all_files = sorted(p.name for p in evidence_dir.iterdir() if p.is_file())

    return {
        "directory": str(evidence_dir),
        "evidence_files": files,
        "all_files": all_files,
        "timestamp": time.time(),
    }


def diff_snapshots(before: dict, after: dict) -> dict:
    changes: list[dict] = []
    new_files: list[str] = []
    removed_files: list[str] = []

    before_files = before.get("evidence_files", {})
    after_files = after.get("evidence_files", {})

    for name in EVIDENCE_FILES:
        b = before_files.get(name, {})
        a = after_files.get(name, {})

        b_missing = b.get("missing", False)
        a_missing = a.get("missing", False)

        if b_missing and not a_missing:
            new_files.append(name)
            changes.append({
                "file": name,
                "change": "created",
                "lines_added": a.get("lines", 0),
            })
        elif not b_missing and a_missing:
            removed_files.append(name)
            changes.append({
                "file": name,
                "change": "removed",
            })
        elif not b_missing and not a_missing:
            line_diff = a.get("lines", 0) - b.get("lines", 0)
            size_diff = a.get("size", 0) - b.get("size", 0)
            if line_diff != 0 or size_diff != 0:
                changes.append({
                    "file": name,
                    "change": "modified",
                    "lines_before": b.get("lines", 0),
                    "lines_after": a.get("lines", 0),
                    "lines_added": line_diff,
                    "size_diff": size_diff,
                })

    before_all = set(before.get("all_files", []))
    after_all = set(after.get("all_files", []))
    for f in sorted(after_all - before_all):
        if f not in [c["file"] for c in changes]:
            new_files.append(f)
    for f in sorted(before_all - after_all):
        if f not in [c["file"] for c in changes]:
            removed_files.append(f)

    return {
        "changed": len(changes) > 0 or len(new_files) > 0 or len(removed_files) > 0,
        "changes": changes,
        "new_files": new_files,
        "removed_files": removed_files,
    }


def format_diff_text(d: dict) -> str:
    if not d["changed"]:
        return "No changes detected.\n"
    lines = []
    for c in d["changes"]:
        if c["change"] == "created":
            lines.append(f"  + {c['file']}: created ({c['lines_added']} lines)")
        elif c["change"] == "removed":
            lines.append(f"  - {c['file']}: removed")
        elif c["change"] == "modified":
            lines.append(f"  ~ {c['file']}: {c['lines_before']} -> {c['lines_after']} lines ({c['lines_added']:+d})")
    for f in d.get("new_files", []):
        lines.append(f"  + {f}: new file")
    for f in d.get("removed_files", []):
        lines.append(f"  - {f}: removed")
    return "\n".join(lines) + "\n"


def watch_evidence(
    evidence_dir: Path,
    interval: float = 2.0,
    on_change: callable = None,
    max_iterations: int | None = None,
) -> None:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    prev = snapshot_evidence(evidence_dir)
    iteration = 0

    print(f"Watching {evidence_dir} (interval: {interval}s, Ctrl+C to stop)", file=sys.stderr)
    stats = evidence_stats(evidence_dir)
    print(f"  Initial: {stats['messages']} messages, {stats['transcripts']} transcripts, {stats['agents']} agents", file=sys.stderr)

    try:
        while True:
            if max_iterations is not None and iteration >= max_iterations:
                break
            time.sleep(interval)
            iteration += 1

            current = snapshot_evidence(evidence_dir)
            d = diff_snapshots(prev, current)

            if d["changed"]:
                print(f"\n[{time.strftime('%H:%M:%S')}] Changes detected:", file=sys.stderr)
                print(format_diff_text(d), file=sys.stderr, end="")

                stats = evidence_stats(evidence_dir)
                print(f"  Now: {stats['messages']} messages, {stats['transcripts']} transcripts, {stats['agents']} agents", file=sys.stderr)

                if on_change is not None:
                    on_change(d, stats)

                prev = current

    except KeyboardInterrupt:
        print("\nWatch stopped.", file=sys.stderr)
