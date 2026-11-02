from __future__ import annotations

import hashlib
import json


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _exact_key(finding: dict) -> str:
    detection = finding.get("detection_type", "")
    agent = finding.get("agent_id_transcript", finding.get("agent_id_control", ""))
    reasons = tuple(sorted(finding.get("reasons", [])))
    raw = f"{detection}|{agent}|{reasons}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _fuzzy_key(finding: dict) -> str:
    detection = finding.get("detection_type", "")
    agent = finding.get("agent_id_transcript", finding.get("agent_id_control", ""))
    return f"{detection}|{agent}"


def _pick_best(group: list[dict]) -> dict:
    def sort_key(f: dict) -> tuple:
        sev = SEVERITY_ORDER.get(f.get("severity", "low"), 0)
        conf = f.get("confidence_score", 0.0)
        return (sev, conf)
    return max(group, key=sort_key)


def deduplicate_findings(
    findings: list[dict],
    *,
    strategy: str = "exact",
) -> tuple[list[dict], list[dict]]:
    if not findings:
        return [], []

    key_fn = _exact_key if strategy == "exact" else _fuzzy_key

    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for f in findings:
        k = key_fn(f)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)

    unique = []
    removed = []
    for k in order:
        group = groups[k]
        best = _pick_best(group)
        unique.append(best)
        for f in group:
            if f is not best:
                removed.append(f)

    return unique, removed


def format_dedup_summary(
    unique: list[dict], removed: list[dict], strategy: str
) -> str:
    total = len(unique) + len(removed)
    lines = [
        f"Deduplicated {total} findings ({strategy} strategy):",
        f"  Unique:  {len(unique)}",
        f"  Removed: {len(removed)}",
    ]
    return "\n".join(lines) + "\n"
