"""Package evidence into a portable zip bundle with manifest."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .stats import EVIDENCE_FILES

_OPTIONAL_FILES = ("ground_truth.json",)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_lines(path: Path) -> int:
    count = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def create_bundle(
    evidence_dir: Path,
    output_path: Path,
    *,
    include_analysis: bool = False,
) -> dict:
    """Create a zip bundle of evidence files with a manifest."""
    evidence_dir = Path(evidence_dir)
    output_path = Path(output_path)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    files_to_bundle: list[dict] = []
    for name in (*EVIDENCE_FILES, *_OPTIONAL_FILES):
        path = evidence_dir / name
        if not path.exists():
            continue
        sha = _sha256(path)
        lines = _count_lines(path) if name.endswith(".jsonl") else 0
        files_to_bundle.append({
            "name": name,
            "sha256": sha,
            "bytes": path.stat().st_size,
            "lines": lines,
        })

    if not files_to_bundle:
        raise ValueError(f"no evidence files found in {evidence_dir}")

    analysis_results: dict | None = None
    if include_analysis:
        from .analyzer import analyze_dataset
        import tempfile

        work = Path(tempfile.mkdtemp(prefix="orbit-bundle-"))
        gt = evidence_dir / "ground_truth.json"
        gt_path = gt if gt.exists() else None
        analysis_results = analyze_dataset(evidence_dir, work, ground_truth_path=gt_path)
        findings_path = work / "findings.json"
        if findings_path.exists():
            files_to_bundle.append({
                "name": "analysis/findings.json",
                "sha256": _sha256(findings_path),
                "bytes": findings_path.stat().st_size,
                "lines": 0,
            })
        summary_path = work / "summary.json"
        if summary_path.exists():
            files_to_bundle.append({
                "name": "analysis/summary.json",
                "sha256": _sha256(summary_path),
                "bytes": summary_path.stat().st_size,
                "lines": 0,
            })

    manifest = {
        "orbit_ir_version": __version__,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(evidence_dir),
        "includes_analysis": include_analysis,
        "files": files_to_bundle,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_size = 0
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in files_to_bundle:
            name = entry["name"]
            if name.startswith("analysis/"):
                src = work / name.removeprefix("analysis/")
            else:
                src = evidence_dir / name
            zf.write(src, name)
            total_size += entry["bytes"]
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))

    return {
        "output": str(output_path),
        "file_count": len(files_to_bundle),
        "total_evidence_bytes": total_size,
        "zip_bytes": output_path.stat().st_size,
        "includes_analysis": include_analysis,
    }


def format_bundle_text(result: dict) -> str:
    lines = [
        f"Bundle: {result['output']}",
        f"  Files:          {result['file_count']}",
        f"  Evidence size:  {result['total_evidence_bytes']} bytes",
        f"  Zip size:       {result['zip_bytes']} bytes",
        f"  Analysis:       {'yes' if result['includes_analysis'] else 'no'}",
    ]
    return "\n".join(lines) + "\n"
