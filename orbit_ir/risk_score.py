from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class DimensionScore:
    name: str
    score: float
    weight: float
    weighted_score: float
    detail: str = ""


@dataclass
class RiskScoreResult:
    composite_score: float = 0.0
    risk_level: str = "low"
    dimensions: list[DimensionScore] = field(default_factory=list)
    total_findings: int = 0
    agent_count: int = 0
    finding_summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SEVERITY_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0}

_DEFAULT_DIM_WEIGHTS = {
    "severity": 0.35,
    "breadth": 0.25,
    "diversity": 0.20,
    "density": 0.20,
}


def compute_risk_score(
    input_path: Path,
    weights: dict[str, float] | None = None,
) -> RiskScoreResult:
    data = json.loads(input_path.read_text(encoding="utf-8"))

    findings: list[dict] = []
    if isinstance(data, dict):
        findings = data.get("findings", data.get("results", []))
    elif isinstance(data, list):
        findings = data

    if not findings:
        return RiskScoreResult()

    w = dict(_DEFAULT_DIM_WEIGHTS)
    if weights:
        w.update(weights)

    agents = set()
    det_types = set()
    sev_counts: dict[str, int] = {}
    for f in findings:
        agents.add(f.get("agent_id", f.get("agent", "unknown")))
        det_types.add(f.get("detection_type", f.get("type", "unknown")))
        sev = f.get("severity", "medium").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    severity_dim = _severity_score(sev_counts)
    breadth_dim = _breadth_score(len(agents))
    diversity_dim = _diversity_score(len(det_types))
    density_dim = _density_score(len(findings), len(agents))

    dims = [
        DimensionScore(
            name="severity",
            score=severity_dim,
            weight=w["severity"],
            weighted_score=severity_dim * w["severity"],
            detail=f"Weighted severity from {sum(sev_counts.values())} findings",
        ),
        DimensionScore(
            name="breadth",
            score=breadth_dim,
            weight=w["breadth"],
            weighted_score=breadth_dim * w["breadth"],
            detail=f"{len(agents)} distinct agent(s) affected",
        ),
        DimensionScore(
            name="diversity",
            score=diversity_dim,
            weight=w["diversity"],
            weighted_score=diversity_dim * w["diversity"],
            detail=f"{len(det_types)} detection type(s) triggered",
        ),
        DimensionScore(
            name="density",
            score=density_dim,
            weight=w["density"],
            weighted_score=density_dim * w["density"],
            detail=f"{len(findings)} findings across {len(agents)} agent(s)",
        ),
    ]

    composite = sum(d.weighted_score for d in dims)
    composite = min(composite, 100.0)

    return RiskScoreResult(
        composite_score=round(composite, 2),
        risk_level=_risk_level(composite),
        dimensions=dims,
        total_findings=len(findings),
        agent_count=len(agents),
        finding_summary=sev_counts,
    )


def _severity_score(sev_counts: dict[str, int]) -> float:
    total_weight = sum(
        _SEVERITY_WEIGHTS.get(sev, 1.0) * cnt for sev, cnt in sev_counts.items()
    )
    max_possible = sum(cnt for cnt in sev_counts.values()) * 10.0
    if max_possible == 0:
        return 0.0
    raw = (total_weight / max_possible) * 100.0
    return min(raw, 100.0)


def _breadth_score(agent_count: int) -> float:
    if agent_count == 0:
        return 0.0
    return min(math.log2(agent_count + 1) * 20.0, 100.0)


def _diversity_score(type_count: int) -> float:
    if type_count == 0:
        return 0.0
    return min(type_count * 15.0, 100.0)


def _density_score(finding_count: int, agent_count: int) -> float:
    if agent_count == 0:
        return 0.0
    ratio = finding_count / agent_count
    return min(ratio * 10.0, 100.0)


def _risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def format_risk_score_text(result: dict) -> str:
    lines = [
        "Composite Risk Assessment",
        "=" * 40,
        f"Risk Score: {result['composite_score']:.1f}/100  Level: {result['risk_level'].upper()}",
        f"Findings: {result['total_findings']}  Agents: {result['agent_count']}",
        "",
        "Dimension Scores:",
        f"  {'Dimension':<12} {'Score':>6} {'Weight':>6} {'Weighted':>8}",
        "  " + "-" * 36,
    ]

    for d in result.get("dimensions", []):
        lines.append(
            f"  {d['name']:<12} {d['score']:6.1f} {d['weight']:6.2f} {d['weighted_score']:8.2f}"
        )

    lines.append("")

    if result.get("finding_summary"):
        lines.append("Severity breakdown:")
        for sev in ("critical", "high", "medium", "low"):
            cnt = result["finding_summary"].get(sev, 0)
            if cnt:
                lines.append(f"  {sev}: {cnt}")
        lines.append("")

    return "\n".join(lines)
