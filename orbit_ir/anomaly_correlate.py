"""Cross-detector anomaly correlation — correlates findings from multiple detectors."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional


@dataclass
class DetectorPair:
    detector_a: str
    detector_b: str
    co_occurrences: int
    total_a: int
    total_b: int
    correlation: float


@dataclass
class AnomalyCluster:
    cluster_id: int
    detectors: List[str]
    event_count: int
    time_span: str
    agents: List[str]


@dataclass
class CorrelationReport:
    pairs: List[DetectorPair]
    detectors_analyzed: int
    total_anomalies: int
    clusters: List[AnomalyCluster]
    strongest_pair: Optional[str] = None


def _load_events(evidence_dir: Path):
    """Load anomaly events from JSON files, extracting detector source."""
    events = []
    edir = Path(evidence_dir)
    if not edir.is_dir():
        return events
    for fpath in sorted(edir.iterdir()):
        if not fpath.suffix == ".json":
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    events.append(item)
        elif isinstance(data, dict):
            if "events" in data and isinstance(data["events"], list):
                for item in data["events"]:
                    if isinstance(item, dict):
                        events.append(item)
            elif "findings" in data and isinstance(data["findings"], list):
                for item in data["findings"]:
                    if isinstance(item, dict):
                        events.append(item)
            else:
                events.append(data)
    return events


def analyze(evidence_dir: Path, window_seconds: float = 300.0) -> CorrelationReport:
    raw = _load_events(evidence_dir)
    if not raw:
        return CorrelationReport(
            pairs=[], detectors_analyzed=0, total_anomalies=0, clusters=[]
        )

    # Group events by detector
    by_detector: Dict[str, list] = defaultdict(list)
    for event in raw:
        detector = event.get("detector", event.get("source", event.get("type", "unknown")))
        by_detector[str(detector)].append(event)

    detectors = sorted(by_detector.keys())
    total = sum(len(v) for v in by_detector.values())

    # Extract timestamps and agents per detector
    def get_ts(e):
        return str(e.get("timestamp", e.get("time", "")))

    def get_agent(e):
        return str(e.get("agent", e.get("agent_id", "unknown")))

    # Compute pairwise correlation based on agent co-occurrence
    pairs: list[DetectorPair] = []
    for i, da in enumerate(detectors):
        for j in range(i + 1, len(detectors)):
            db = detectors[j]
            agents_a = {get_agent(e) for e in by_detector[da]}
            agents_b = {get_agent(e) for e in by_detector[db]}
            shared = agents_a & agents_b
            union = agents_a | agents_b
            corr = len(shared) / len(union) if union else 0.0
            pairs.append(DetectorPair(
                detector_a=da,
                detector_b=db,
                co_occurrences=len(shared),
                total_a=len(by_detector[da]),
                total_b=len(by_detector[db]),
                correlation=round(corr, 4),
            ))

    pairs.sort(key=lambda p: p.correlation, reverse=True)

    strongest = None
    if pairs and pairs[0].correlation > 0:
        strongest = f"{pairs[0].detector_a} <-> {pairs[0].detector_b} ({pairs[0].correlation:.0%})"

    # Build clusters: group detectors that share agents
    clusters: list[AnomalyCluster] = []
    agent_detectors: Dict[str, set] = defaultdict(set)
    for det, evts in by_detector.items():
        for e in evts:
            agent_detectors[get_agent(e)].add(det)

    cluster_id = 0
    seen_agents = set()
    for agent, dets in sorted(agent_detectors.items(), key=lambda x: -len(x[1])):
        if len(dets) < 2 or agent in seen_agents:
            continue
        cluster_id += 1
        related_agents = [agent]
        for other_agent, other_dets in agent_detectors.items():
            if other_agent != agent and other_dets & dets and other_agent not in seen_agents:
                related_agents.append(other_agent)
                seen_agents.add(other_agent)
        seen_agents.add(agent)
        event_count = sum(
            len([e for e in by_detector[d] if get_agent(e) in set(related_agents)])
            for d in dets
        )
        clusters.append(AnomalyCluster(
            cluster_id=cluster_id,
            detectors=sorted(dets),
            event_count=event_count,
            time_span="n/a",
            agents=sorted(related_agents),
        ))

    clusters.sort(key=lambda c: c.event_count, reverse=True)

    return CorrelationReport(
        pairs=pairs,
        detectors_analyzed=len(detectors),
        total_anomalies=total,
        clusters=clusters[:20],
        strongest_pair=strongest,
    )


def format_text(report: CorrelationReport) -> str:
    lines = [
        "Cross-Detector Anomaly Correlation",
        "=" * 62,
        "",
    ]
    if report.detectors_analyzed == 0:
        lines.append("  No anomaly events to correlate.")
        return "\n".join(lines) + "\n"

    lines.append(f"  Detectors analyzed:  {report.detectors_analyzed}")
    lines.append(f"  Total anomalies:     {report.total_anomalies}")
    lines.append(f"  Correlations:        {len(report.pairs)}")
    lines.append(f"  Clusters:            {len(report.clusters)}")
    if report.strongest_pair:
        lines.append(f"  Strongest pair:      {report.strongest_pair}")
    lines.append("")

    if report.pairs:
        lines.append("Detector Pairs")
        lines.append("-" * 62)
        for p in report.pairs[:15]:
            lines.append(
                f"  {p.detector_a} <-> {p.detector_b}  "
                f"corr={p.correlation:.0%}  co={p.co_occurrences}  "
                f"({p.total_a}+{p.total_b} events)"
            )
        if len(report.pairs) > 15:
            lines.append(f"  ... and {len(report.pairs) - 15} more")
        lines.append("")

    if report.clusters:
        lines.append("Anomaly Clusters")
        lines.append("-" * 62)
        for c in report.clusters[:10]:
            lines.append(
                f"  Cluster {c.cluster_id}: {', '.join(c.detectors)}  "
                f"events={c.event_count}  agents={', '.join(c.agents[:5])}"
            )
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: CorrelationReport) -> str:
    d = asdict(report)
    return json.dumps(d, indent=2) + "\n"
