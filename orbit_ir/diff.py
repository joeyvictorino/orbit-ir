"""Compare two orbit-ir analysis results directories."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def load_results(results_dir: Path) -> tuple[dict, list[dict]]:
    """Load summary.json and findings.csv from a results directory."""
    summary_path = results_dir / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"No summary.json in {results_dir}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    findings: list[dict] = []
    csv_path = results_dir / "findings.csv"
    if csv_path.exists():
        with csv_path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                findings.append(row)
    return summary, findings


def _finding_key(f: dict) -> str:
    """Stable dedup key for a finding: tool_call_id is unique per finding."""
    return f.get("tool_call_id", f.get("finding_id", ""))


def diff_results(before_dir: Path, after_dir: Path) -> dict:
    """Compare two results directories and return a structured diff."""
    before_summary, before_findings = load_results(before_dir)
    after_summary, after_findings = load_results(after_dir)

    before_by_key = {_finding_key(f): f for f in before_findings}
    after_by_key = {_finding_key(f): f for f in after_findings}

    before_keys = set(before_by_key)
    after_keys = set(after_by_key)

    new_keys = after_keys - before_keys
    resolved_keys = before_keys - after_keys
    common_keys = before_keys & after_keys

    changed: list[dict] = []
    for key in sorted(common_keys):
        bf = before_by_key[key]
        af = after_by_key[key]
        diffs = {}
        for field in ("confidence", "confidence_score", "reasons", "effect"):
            bv = bf.get(field, "")
            av = af.get(field, "")
            if bv != av:
                diffs[field] = {"before": bv, "after": av}
        if diffs:
            changed.append({"tool_call_id": key, "changes": diffs})

    corpus_delta = _dict_delta(
        before_summary.get("corpus", {}),
        after_summary.get("corpus", {}),
    )
    findings_delta = _dict_delta(
        before_summary.get("findings", {}),
        after_summary.get("findings", {}),
    )

    return {
        "before_dir": str(before_dir),
        "after_dir": str(after_dir),
        "before_total_findings": len(before_findings),
        "after_total_findings": len(after_findings),
        "new_findings": [after_by_key[k] for k in sorted(new_keys)],
        "resolved_findings": [before_by_key[k] for k in sorted(resolved_keys)],
        "changed_findings": changed,
        "corpus_delta": corpus_delta,
        "findings_summary_delta": findings_delta,
    }


def _dict_delta(before: dict, after: dict) -> dict:
    """Compare two flat dicts, returning fields that changed."""
    delta: dict = {}
    all_keys = sorted(set(before) | set(after))
    for k in all_keys:
        bv = before.get(k)
        av = after.get(k)
        if isinstance(bv, (int, float)) and isinstance(av, (int, float)):
            if bv != av:
                delta[k] = {"before": bv, "after": av, "delta": av - bv}
        elif bv != av:
            delta[k] = {"before": bv, "after": av}
    return delta


def format_diff_text(result: dict) -> str:
    """Render a diff result as human-readable text."""
    lines: list[str] = []
    lines.append("orbit-ir diff")
    lines.append(f"  before: {result['before_dir']} ({result['before_total_findings']} findings)")
    lines.append(f"  after:  {result['after_dir']} ({result['after_total_findings']} findings)")
    lines.append("")

    new = result["new_findings"]
    resolved = result["resolved_findings"]
    changed = result["changed_findings"]

    if not new and not resolved and not changed and not result["corpus_delta"] and not result["findings_summary_delta"]:
        lines.append("No differences found.")
        return "\n".join(lines)

    if new:
        lines.append(f"NEW findings ({len(new)}):")
        for f in new:
            reasons = f.get("reasons", "")
            lines.append(f"  + {f.get('finding_id', '?')} [{f.get('confidence', '?')}] {reasons}")
        lines.append("")

    if resolved:
        lines.append(f"RESOLVED findings ({len(resolved)}):")
        for f in resolved:
            reasons = f.get("reasons", "")
            lines.append(f"  - {f.get('finding_id', '?')} [{f.get('confidence', '?')}] {reasons}")
        lines.append("")

    if changed:
        lines.append(f"CHANGED findings ({len(changed)}):")
        for c in changed:
            parts = [f"{k}: {v['before']} → {v['after']}" for k, v in c["changes"].items()]
            lines.append(f"  ~ {c['tool_call_id']}: {', '.join(parts)}")
        lines.append("")

    corpus_delta = result.get("corpus_delta", {})
    if corpus_delta:
        lines.append("Corpus changes:")
        for k, v in sorted(corpus_delta.items()):
            if "delta" in v:
                sign = "+" if v["delta"] > 0 else ""
                lines.append(f"  {k}: {v['before']} → {v['after']} ({sign}{v['delta']})")
            else:
                lines.append(f"  {k}: {v['before']} → {v['after']}")
        lines.append("")

    findings_delta = result.get("findings_summary_delta", {})
    if findings_delta:
        lines.append("Findings summary changes:")
        for k, v in sorted(findings_delta.items()):
            if "delta" in v:
                sign = "+" if v["delta"] > 0 else ""
                lines.append(f"  {k}: {v['before']} → {v['after']} ({sign}{v['delta']})")
            else:
                lines.append(f"  {k}: {v['before']} → {v['after']}")
        lines.append("")

    return "\n".join(lines)
