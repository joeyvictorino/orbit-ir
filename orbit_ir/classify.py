"""Heuristic event classification for agent event streams."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SUSPICIOUS_TYPES = {
    "privilege_escalation", "credential_access", "lateral_movement",
    "data_exfiltration", "persistence", "defense_evasion", "execution",
    "command_and_control",
}

MALICIOUS_INDICATORS = {
    "data_exfiltration", "credential_access", "persistence",
    "command_and_control",
}

SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _classify_event(ev: dict[str, Any]) -> str:
    ev_type = ev.get("type", "").lower()
    severity = ev.get("severity", "").lower()

    if ev_type in MALICIOUS_INDICATORS:
        return "malicious"
    if ev_type in SUSPICIOUS_TYPES:
        return "suspicious"
    if severity in ("critical", "high"):
        return "suspicious"
    return "benign"


def _score_event(ev: dict[str, Any], label: str) -> float:
    base = {"malicious": 1.0, "suspicious": 0.5, "benign": 0.0}[label]
    sev = ev.get("severity", "").lower()
    sev_bonus = SEVERITY_WEIGHTS.get(sev, 0) * 0.1
    return round(min(base + sev_bonus, 1.0), 2)


def classify_events(
    input_path: Path,
    *,
    threshold: float = 0.5,
) -> dict[str, Any]:
    events = _load_events(input_path)
    classified: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for ev in events:
        label = _classify_event(ev)
        score = _score_event(ev, label)
        counts[label] += 1
        classified.append({
            "event_id": ev.get("event_id", ""),
            "agent_id": ev.get("agent_id", ""),
            "type": ev.get("type", ""),
            "label": label,
            "confidence": score,
        })

    high_risk = [c for c in classified if c["confidence"] >= threshold]
    high_risk.sort(key=lambda x: x["confidence"], reverse=True)

    return {
        "total_events": len(events),
        "classifications": classified,
        "summary": dict(counts),
        "high_risk_count": len(high_risk),
        "high_risk": high_risk,
        "threshold": threshold,
    }


def format_classify_text(result: dict[str, Any]) -> str:
    lines = [
        f"Event Classification ({result['total_events']} events)",
        "=" * 50,
        "",
    ]
    summary = result.get("summary", {})
    for label in ("malicious", "suspicious", "benign"):
        count = summary.get(label, 0)
        lines.append(f"  {label:12s}: {count}")
    lines.append("")

    high = result.get("high_risk", [])
    if high:
        lines.append(f"High-risk events (>= {result['threshold']} confidence):")
        for item in high[:20]:
            lines.append(
                f"  [{item['confidence']:.2f}] {item['label']:10s} "
                f"{item['event_id']} ({item['type']})"
            )
        if len(high) > 20:
            lines.append(f"  ... and {len(high) - 20} more")
    else:
        lines.append("No high-risk events detected.")

    return "\n".join(lines)
