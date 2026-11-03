from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analyzer import analyze_dataset


def _hash_findings(findings: list[dict]) -> str:
    canonical = json.dumps(findings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def audit_reproducibility(
    evidence_dir: Path,
    reference_dir: Path,
    *,
    work_dir: Path,
) -> dict:
    ref_findings_path = reference_dir / "findings.json"
    if not ref_findings_path.exists():
        raise FileNotFoundError(f"reference findings not found: {ref_findings_path}")

    ref_findings = json.loads(ref_findings_path.read_text(encoding="utf-8"))
    ref_hash = _hash_findings(ref_findings)

    ground_truth = evidence_dir / "ground_truth.json"
    gt_path = ground_truth if ground_truth.exists() else None
    analyze_dataset(evidence_dir, work_dir, ground_truth_path=gt_path)

    new_findings_path = work_dir / "findings.json"
    new_findings = json.loads(new_findings_path.read_text(encoding="utf-8"))
    new_hash = _hash_findings(new_findings)

    reproducible = ref_hash == new_hash

    ref_types = {f.get("detection_type", "") for f in ref_findings}
    new_types = {f.get("detection_type", "") for f in new_findings}
    added_types = sorted(new_types - ref_types)
    removed_types = sorted(ref_types - new_types)

    return {
        "reproducible": reproducible,
        "reference_hash": ref_hash,
        "rerun_hash": new_hash,
        "reference_count": len(ref_findings),
        "rerun_count": len(new_findings),
        "added_detection_types": added_types,
        "removed_detection_types": removed_types,
    }


def format_audit_text(result: dict) -> str:
    status = "REPRODUCIBLE" if result["reproducible"] else "DIVERGED"
    lines = [
        f"Audit: {status}",
        f"  Reference: {result['reference_count']} findings (hash: {result['reference_hash'][:12]}...)",
        f"  Rerun:     {result['rerun_count']} findings (hash: {result['rerun_hash'][:12]}...)",
    ]
    if result["added_detection_types"]:
        lines.append(f"  New types:     {', '.join(result['added_detection_types'])}")
    if result["removed_detection_types"]:
        lines.append(f"  Missing types: {', '.join(result['removed_detection_types'])}")
    return "\n".join(lines) + "\n"
