"""Evidence attribution analysis — traces each evidence item to its source agent/action."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AttributionSource:
    name: str
    source_type: str  # "agent", "external", "system", "human"
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Attribution:
    evidence_id: str
    source: AttributionSource
    timestamp: str = ""
    action: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    chain: list[str] = field(default_factory=list)


@dataclass
class AttributionReport:
    attributions: list[Attribution] = field(default_factory=list)
    unattributed: list[str] = field(default_factory=list)
    sources: list[AttributionSource] = field(default_factory=list)
    confidence_distribution: dict[str, int] = field(default_factory=dict)


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    elif path.is_dir():
        for f in sorted(path.iterdir()):
            if f.suffix in (".json", ".jsonl"):
                events.extend(_load_events(f))
    return events


def compute_confidence(evidence: dict, timeline_entry: dict) -> float:
    score = 0.0
    weights = 0.0

    e_ts = evidence.get("timestamp", "")
    t_ts = timeline_entry.get("timestamp", "")
    if e_ts and t_ts:
        weights += 0.4
        if e_ts == t_ts:
            score += 0.4
        elif e_ts[:16] == t_ts[:16]:
            score += 0.3
        elif e_ts[:13] == t_ts[:13]:
            score += 0.2

    e_agent = evidence.get("agent_id", evidence.get("agent", ""))
    t_agent = timeline_entry.get("agent_id", timeline_entry.get("agent", ""))
    if e_agent and t_agent:
        weights += 0.35
        if e_agent == t_agent:
            score += 0.35

    e_action = evidence.get("action", evidence.get("event_type", ""))
    t_action = timeline_entry.get("action", timeline_entry.get("event_type", ""))
    if e_action and t_action:
        weights += 0.25
        if e_action == t_action:
            score += 0.25
        elif e_action.lower() == t_action.lower():
            score += 0.15

    if weights == 0:
        return 0.0
    return round(score / weights, 3)


def build_attribution_chain(evidence_id: str, timeline: list[dict]) -> list[str]:
    chain: list[str] = []
    for entry in timeline:
        eid = entry.get("evidence_id", entry.get("id", ""))
        if eid == evidence_id:
            agent = entry.get("agent_id", entry.get("agent", "unknown"))
            action = entry.get("action", entry.get("event_type", "unknown"))
            ts = entry.get("timestamp", "?")
            chain.append(f"{ts}: {agent} -> {action}")
        refs = entry.get("references", [])
        if evidence_id in refs:
            agent = entry.get("agent_id", entry.get("agent", "unknown"))
            action = entry.get("action", entry.get("event_type", "ref"))
            ts = entry.get("timestamp", "?")
            chain.append(f"{ts}: {agent} -> {action} (ref)")
    return chain


def _classify_source(agent_name: str) -> str:
    lower = agent_name.lower()
    if any(k in lower for k in ("system", "kernel", "os", "scheduler")):
        return "system"
    if any(k in lower for k in ("human", "operator", "analyst", "user")):
        return "human"
    if any(k in lower for k in ("external", "feed", "ioc", "threat")):
        return "external"
    return "agent"


def attribute_evidence(
    timeline: list[dict],
    evidence: list[dict],
    min_confidence: float = 0.0,
) -> AttributionReport:
    report = AttributionReport()
    source_map: dict[str, AttributionSource] = {}

    for ev in evidence:
        ev_id = ev.get("id", ev.get("evidence_id", ""))
        best_conf = 0.0
        best_entry: dict | None = None

        for entry in timeline:
            conf = compute_confidence(ev, entry)
            if conf > best_conf:
                best_conf = conf
                best_entry = entry

        if best_entry is None or best_conf < min_confidence:
            if ev_id:
                report.unattributed.append(ev_id)
            continue

        agent_name = best_entry.get("agent_id", best_entry.get("agent", "unknown"))
        src_type = _classify_source(agent_name)

        if agent_name not in source_map:
            source_map[agent_name] = AttributionSource(
                name=agent_name, source_type=src_type
            )
        src = source_map[agent_name]
        if ev_id:
            src.evidence_ids.append(ev_id)
        src.confidence = max(src.confidence, best_conf)

        chain = build_attribution_chain(ev_id, timeline) if ev_id else []

        attr = Attribution(
            evidence_id=ev_id,
            source=src,
            timestamp=best_entry.get("timestamp", ""),
            action=best_entry.get("action", best_entry.get("event_type", "")),
            context={"matched_confidence": best_conf},
            chain=chain,
        )
        report.attributions.append(attr)

    report.sources = list(source_map.values())

    dist: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for a in report.attributions:
        conf = a.context.get("matched_confidence", 0)
        if conf >= 0.8:
            dist["high"] += 1
        elif conf >= 0.5:
            dist["medium"] += 1
        else:
            dist["low"] += 1
    report.confidence_distribution = dist

    return report


def summarize_attributions(report: AttributionReport) -> dict:
    return {
        "total_evidence": len(report.attributions) + len(report.unattributed),
        "attributed": len(report.attributions),
        "unattributed": len(report.unattributed),
        "sources": len(report.sources),
        "confidence_distribution": report.confidence_distribution,
        "source_types": {
            s.source_type: sum(1 for src in report.sources if src.source_type == s.source_type)
            for s in report.sources
        },
    }


def format_attribution_text(report: AttributionReport) -> str:
    lines: list[str] = []
    lines.append("Evidence Attribution Report")
    lines.append("=" * 60)
    lines.append("")

    summary = summarize_attributions(report)
    lines.append(f"  Total evidence items: {summary['total_evidence']}")
    lines.append(f"  Attributed:           {summary['attributed']}")
    lines.append(f"  Unattributed:         {summary['unattributed']}")
    lines.append(f"  Unique sources:       {summary['sources']}")
    lines.append("")

    if report.confidence_distribution:
        lines.append("  Confidence Distribution:")
        for level, count in sorted(report.confidence_distribution.items()):
            lines.append(f"    {level:>8}: {count}")
        lines.append("")

    if report.attributions:
        lines.append(f"  {'Evidence ID':<20} {'Source':<20} {'Type':<10} {'Conf':>6}")
        lines.append("  " + "-" * 60)
        for a in report.attributions:
            conf = a.context.get("matched_confidence", 0)
            lines.append(
                f"  {a.evidence_id:<20} {a.source.name:<20} {a.source.source_type:<10} {conf:>6.3f}"
            )
        lines.append("")

    if report.unattributed:
        lines.append("  Unattributed evidence:")
        for uid in report.unattributed:
            lines.append(f"    - {uid}")
        lines.append("")

    return "\n".join(lines) + "\n"


def load_and_attribute(
    timeline_path: Path,
    evidence_path: Path,
    min_confidence: float = 0.0,
) -> AttributionReport:
    timeline = _load_events(timeline_path)
    evidence = _load_events(evidence_path)
    return attribute_evidence(timeline, evidence, min_confidence=min_confidence)
