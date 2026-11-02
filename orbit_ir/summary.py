"""Executive summary generator for orbit-ir analysis results.

Reads summary.json and findings.json from an analysis output directory
and produces a concise executive summary with key risk indicators,
severity breakdown, top patterns, and actionable recommendations.
"""
from __future__ import annotations

import json
from pathlib import Path


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_executive_summary(results_dir: Path) -> dict:
    summary_path = results_dir / "summary.json"
    findings_path = results_dir / "findings.json"

    if not summary_path.exists():
        raise FileNotFoundError(f"{summary_path} not found — run analyze first")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    corpus = summary.get("corpus", {})
    findings_meta = summary.get("findings", {})

    all_findings: list[dict] = []
    if findings_path.exists():
        all_findings = json.loads(findings_path.read_text(encoding="utf-8"))

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    detection_types: dict[str, int] = {}
    affected_agents: set[str] = set()
    mitre_techniques: dict[str, int] = {}

    for f in all_findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        det = f.get("detection_type", f.get("reason", "unknown"))
        detection_types[det] = detection_types.get(det, 0) + 1

        agent = f.get("agent_id")
        if agent:
            affected_agents.add(agent)

        for tech in f.get("mitre_techniques", []):
            tid = tech if isinstance(tech, str) else tech.get("technique_id", "")
            if tid:
                mitre_techniques[tid] = mitre_techniques.get(tid, 0) + 1

    top_detection_types = sorted(
        detection_types.items(), key=lambda x: x[1], reverse=True
    )[:5]

    top_mitre = sorted(
        mitre_techniques.items(), key=lambda x: x[1], reverse=True
    )[:5]

    risk_score = findings_meta.get("risk_score", 0)
    risk_rating = findings_meta.get("risk_rating", "unknown")

    recommendations = _generate_recommendations(
        severity_counts, detection_types, findings_meta
    )

    return {
        "overview": {
            "scenario": summary.get("scenario", ""),
            "corpus_agents": corpus.get("agents", 0),
            "corpus_messages": corpus.get("messages", 0),
            "time_range": {
                "start": corpus.get("first_timestamp"),
                "end": corpus.get("last_timestamp"),
            },
            "total_findings": len(all_findings),
            "risk_score": risk_score,
            "risk_rating": risk_rating,
        },
        "severity_breakdown": severity_counts,
        "top_detection_types": [
            {"type": t, "count": c} for t, c in top_detection_types
        ],
        "top_mitre_techniques": [
            {"technique": t, "count": c} for t, c in top_mitre
        ],
        "affected_agents": {
            "count": len(affected_agents),
            "ids": sorted(affected_agents)[:20],
        },
        "confidence": {
            "bands": findings_meta.get("confidence_bands", {}),
            "average_score": findings_meta.get("average_confidence_score", 0),
        },
        "key_indicators": {
            "coordinators_detected": findings_meta.get("coordinators_over_threshold", 0),
            "lateral_movement": findings_meta.get("lateral_movement_detections", 0),
            "shared_credentials": findings_meta.get("shared_credentials", 0),
            "agent_clusters": findings_meta.get("agent_clusters", 0),
            "oracle_violations": findings_meta.get("oracle_integrity_violations", 0),
        },
        "recommendations": recommendations,
    }


def _generate_recommendations(
    severity_counts: dict[str, int],
    detection_types: dict[str, int],
    findings_meta: dict,
) -> list[dict]:
    recs: list[dict] = []

    if severity_counts.get("critical", 0) > 0:
        recs.append({
            "priority": "critical",
            "action": "Investigate critical-severity findings immediately",
            "detail": f"{severity_counts['critical']} critical finding(s) require urgent triage — "
                      "these indicate confirmed evidence tampering or privilege escalation.",
        })

    if findings_meta.get("coordinators_over_threshold", 0) > 0:
        recs.append({
            "priority": "high",
            "action": "Review detected coordinator agents",
            "detail": f"{findings_meta['coordinators_over_threshold']} agent(s) show coordination "
                      "patterns — verify whether their delegation authority is sanctioned.",
        })

    if findings_meta.get("lateral_movement_detections", 0) > 0:
        recs.append({
            "priority": "high",
            "action": "Audit lateral movement between agents",
            "detail": f"{findings_meta['lateral_movement_detections']} lateral-movement event(s) "
                      "detected — check for credential sharing or unauthorized cross-agent access.",
        })

    spoofs = detection_types.get("tool-name-mismatch", 0) + detection_types.get(
        "transcript-tool-call-mismatch", 0
    )
    if spoofs > 0:
        recs.append({
            "priority": "high",
            "action": "Verify tool-call integrity",
            "detail": f"{spoofs} tool-call mismatch(es) between transcript and control plane — "
                      "cross-reference with execution logs.",
        })

    if findings_meta.get("shared_credentials", 0) > 0:
        recs.append({
            "priority": "medium",
            "action": "Rotate shared credentials",
            "detail": f"{findings_meta['shared_credentials']} credential(s) appear shared across "
                      "agents — rotate and enforce per-agent credential issuance.",
        })

    oracle = findings_meta.get("oracle_integrity_violations", 0)
    if oracle > 0:
        recs.append({
            "priority": "medium",
            "action": "Review oracle integrity violations",
            "detail": f"{oracle} oracle integrity violation(s) suggest evaluation results "
                      "may have been modified after generation.",
        })

    if not recs:
        recs.append({
            "priority": "info",
            "action": "No immediate actions required",
            "detail": "Analysis found no high-priority indicators. "
                      "Continue routine monitoring.",
        })

    return recs


def format_summary_text(summary: dict) -> str:
    lines: list[str] = []
    ov = summary["overview"]

    lines.append("=" * 60)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Risk Rating: {ov['risk_rating'].upper()} (score: {ov['risk_score']:.1f})")
    lines.append(f"Total Findings: {ov['total_findings']}")
    lines.append(f"Corpus: {ov['corpus_agents']} agents, {ov['corpus_messages']:,} messages")

    tr = ov.get("time_range", {})
    if tr.get("start") and tr.get("end"):
        lines.append(f"Time Range: {tr['start']} to {tr['end']}")
    lines.append("")

    lines.append("Severity Breakdown:")
    sev = summary["severity_breakdown"]
    for level in ("critical", "high", "medium", "low"):
        count = sev.get(level, 0)
        bar = "#" * min(count, 40)
        lines.append(f"  {level:>8}: {count:>4}  {bar}")
    lines.append("")

    if summary["top_detection_types"]:
        lines.append("Top Detection Types:")
        for item in summary["top_detection_types"]:
            lines.append(f"  {item['count']:>4}  {item['type']}")
        lines.append("")

    ki = summary["key_indicators"]
    lines.append("Key Indicators:")
    lines.append(f"  Coordinators detected: {ki['coordinators_detected']}")
    lines.append(f"  Lateral movement:      {ki['lateral_movement']}")
    lines.append(f"  Shared credentials:    {ki['shared_credentials']}")
    lines.append(f"  Agent clusters:        {ki['agent_clusters']}")
    lines.append(f"  Oracle violations:     {ki['oracle_violations']}")
    lines.append("")

    lines.append("Recommendations:")
    for rec in summary["recommendations"]:
        lines.append(f"  [{rec['priority'].upper()}] {rec['action']}")
        lines.append(f"         {rec['detail']}")
    lines.append("")

    return "\n".join(lines)
