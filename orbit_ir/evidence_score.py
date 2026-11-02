from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class QualityDimension:
    name: str
    score: float
    weight: float
    weighted_score: float
    detail: str = ""


@dataclass
class FileQuality:
    path: str
    record_count: int = 0
    completeness: float = 0.0
    consistency: float = 0.0
    issues: list[str] = field(default_factory=list)


@dataclass
class EvidenceScoreResult:
    overall_score: float = 0.0
    quality_level: str = "unknown"
    dimensions: list[QualityDimension] = field(default_factory=list)
    file_scores: list[FileQuality] = field(default_factory=list)
    total_records: int = 0
    total_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_REQUIRED_FIELDS = {
    "agents.jsonl": ["agent_id", "name"],
    "messages.jsonl": ["message_id", "agent_id", "content"],
    "transcripts.jsonl": ["transcript_id", "agent_id"],
    "tool_calls.jsonl": ["call_id", "agent_id", "tool_name"],
}

_EXPECTED_FILES = [
    "agents.jsonl",
    "messages.jsonl",
    "transcripts.jsonl",
    "tool_calls.jsonl",
]

_DIM_WEIGHTS = {
    "completeness": 0.30,
    "consistency": 0.25,
    "coverage": 0.25,
    "volume": 0.20,
}


def score_evidence(
    input_path: Path,
    weights: dict[str, float] | None = None,
) -> EvidenceScoreResult:
    p = Path(input_path)

    w = dict(_DIM_WEIGHTS)
    if weights:
        w.update(weights)

    files_found: list[Path] = []
    if p.is_file():
        files_found = [p]
    elif p.is_dir():
        files_found = sorted(
            f for f in p.iterdir()
            if f.is_file() and f.suffix in (".jsonl", ".json")
        )

    if not files_found:
        return EvidenceScoreResult(quality_level="none")

    file_scores: list[FileQuality] = []
    total_records = 0
    all_agent_ids: set[str] = set()
    files_present: set[str] = set()

    for fp in files_found:
        fq = _score_file(fp)
        file_scores.append(fq)
        total_records += fq.record_count
        files_present.add(fp.name)
        _collect_agent_ids(fp, all_agent_ids)

    completeness_score = _completeness_score(file_scores)
    consistency_score = _consistency_score(file_scores)
    coverage_score = _coverage_score(files_present)
    volume_score = _volume_score(total_records)

    dims = [
        QualityDimension(
            name="completeness",
            score=completeness_score,
            weight=w["completeness"],
            weighted_score=completeness_score * w["completeness"],
            detail=f"Field completeness across {len(file_scores)} file(s)",
        ),
        QualityDimension(
            name="consistency",
            score=consistency_score,
            weight=w["consistency"],
            weighted_score=consistency_score * w["consistency"],
            detail=f"Record consistency across {total_records} record(s)",
        ),
        QualityDimension(
            name="coverage",
            score=coverage_score,
            weight=w["coverage"],
            weighted_score=coverage_score * w["coverage"],
            detail=f"{len(files_present)} of {len(_EXPECTED_FILES)} expected file(s) present",
        ),
        QualityDimension(
            name="volume",
            score=volume_score,
            weight=w["volume"],
            weighted_score=volume_score * w["volume"],
            detail=f"{total_records} total record(s)",
        ),
    ]

    overall = sum(d.weighted_score for d in dims)
    overall = min(overall, 100.0)

    return EvidenceScoreResult(
        overall_score=round(overall, 2),
        quality_level=_quality_level(overall),
        dimensions=dims,
        file_scores=file_scores,
        total_records=total_records,
        total_files=len(files_found),
    )


def _score_file(fp: Path) -> FileQuality:
    issues: list[str] = []
    records: list[dict] = []

    try:
        text = fp.read_text(encoding="utf-8")
    except Exception as e:
        return FileQuality(path=str(fp), issues=[f"read error: {e}"])

    if fp.suffix == ".jsonl":
        for i, line in enumerate(text.strip().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                issues.append(f"line {i}: invalid JSON")
    elif fp.suffix == ".json":
        try:
            data = json.loads(text)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                records = data.get("findings", data.get("results", data.get("records", [data])))
        except json.JSONDecodeError:
            issues.append("invalid JSON file")

    if not records:
        return FileQuality(path=str(fp), issues=issues or ["empty file"])

    required = _REQUIRED_FIELDS.get(fp.name, [])
    missing_counts = 0
    total_checks = 0

    for rec in records:
        for field_name in required:
            total_checks += 1
            if field_name not in rec or rec[field_name] is None:
                missing_counts += 1

    completeness = ((total_checks - missing_counts) / total_checks * 100.0) if total_checks > 0 else 100.0

    all_keys: set[str] = set()
    for rec in records:
        all_keys.update(rec.keys())
    key_presence = {}
    for k in all_keys:
        key_presence[k] = sum(1 for r in records if k in r)
    inconsistent = sum(1 for k, c in key_presence.items() if 0 < c < len(records))
    consistency = ((len(all_keys) - inconsistent) / len(all_keys) * 100.0) if all_keys else 100.0

    if missing_counts > 0:
        issues.append(f"{missing_counts} missing required field(s)")
    if inconsistent > 0:
        issues.append(f"{inconsistent} inconsistent field(s)")

    return FileQuality(
        path=str(fp),
        record_count=len(records),
        completeness=round(completeness, 1),
        consistency=round(consistency, 1),
        issues=issues,
    )


def _collect_agent_ids(fp: Path, ids: set[str]) -> None:
    try:
        text = fp.read_text(encoding="utf-8")
    except Exception:
        return
    if fp.suffix == ".jsonl":
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                aid = rec.get("agent_id")
                if aid:
                    ids.add(str(aid))
            except json.JSONDecodeError:
                pass


def _completeness_score(files: list[FileQuality]) -> float:
    if not files:
        return 0.0
    return sum(f.completeness for f in files) / len(files)


def _consistency_score(files: list[FileQuality]) -> float:
    if not files:
        return 0.0
    return sum(f.consistency for f in files) / len(files)


def _coverage_score(present: set[str]) -> float:
    if not _EXPECTED_FILES:
        return 100.0
    covered = sum(1 for ef in _EXPECTED_FILES if ef in present)
    return covered / len(_EXPECTED_FILES) * 100.0


def _volume_score(total: int) -> float:
    if total == 0:
        return 0.0
    if total >= 10000:
        return 100.0
    if total >= 1000:
        return 80.0
    if total >= 100:
        return 60.0
    if total >= 10:
        return 40.0
    return 20.0


def _quality_level(score: float) -> str:
    if score >= 80:
        return "excellent"
    if score >= 60:
        return "good"
    if score >= 40:
        return "adequate"
    if score >= 20:
        return "poor"
    return "insufficient"


def format_evidence_score_text(result: dict) -> str:
    lines = [
        "Evidence Quality Score",
        "=" * 40,
        f"Overall Score: {result['overall_score']:.1f}/100  Quality: {result['quality_level'].upper()}",
        f"Files: {result['total_files']}  Records: {result['total_records']}",
        "",
        "Quality Dimensions:",
        f"  {'Dimension':<14} {'Score':>6} {'Weight':>6} {'Weighted':>8}",
        "  " + "-" * 38,
    ]

    for d in result.get("dimensions", []):
        lines.append(
            f"  {d['name']:<14} {d['score']:6.1f} {d['weight']:6.2f} {d['weighted_score']:8.2f}"
        )

    lines.append("")

    if result.get("file_scores"):
        lines.append("File Details:")
        for fs in result["file_scores"]:
            path = Path(fs["path"]).name
            lines.append(f"  {path}: {fs['record_count']} records, completeness={fs['completeness']:.1f}%, consistency={fs['consistency']:.1f}%")
            for issue in fs.get("issues", []):
                lines.append(f"    - {issue}")

    lines.append("")
    return "\n".join(lines)
