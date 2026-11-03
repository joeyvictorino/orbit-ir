"""Data flow tracing through agent interactions.

Builds a directed graph of data movement across agents, tracks provenance
(source → transform → sink → egress), assigns sensitivity labels, and
detects exfiltration patterns.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


_SENSITIVITY_KEYWORDS: dict[str, str] = {
    "secret": "high",
    "credential": "high",
    "password": "high",
    "token": "high",
    "key": "high",
    "private": "high",
    "pii": "high",
    "ssn": "high",
    "credit_card": "high",
    "config": "medium",
    "internal": "medium",
    "audit": "medium",
    "log": "low",
    "metric": "low",
    "status": "low",
    "health": "low",
}

_EXTERNAL_MARKERS = (
    "external", "public", "internet", "s3://", "https://", "http://",
    "cloud", "cdn", "upload", "export", "outbound",
)

_STORE_MARKERS = (
    "database", "db", "redis", "postgres", "mysql", "mongo", "s3",
    "bucket", "storage", "disk", "file", "volume", "cache",
)

_SENSITIVITY_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events


def _classify_sensitivity(text: str) -> str:
    lower = text.lower()
    best = "none"
    for keyword, level in _SENSITIVITY_KEYWORDS.items():
        if keyword in lower and _SENSITIVITY_RANK[level] > _SENSITIVITY_RANK[best]:
            best = level
    return best


def _is_external(text: str) -> bool:
    lower = text.lower()
    return any(m in lower for m in _EXTERNAL_MARKERS)


def _is_store(text: str) -> bool:
    lower = text.lower()
    return any(m in lower for m in _STORE_MARKERS)


@dataclass
class DataFlowEdge:
    source: str
    target: str
    data_type: str
    sensitivity: str
    event_count: int = 1
    total_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExfiltrationAlert:
    source_agent: str
    destination: str
    data_type: str
    sensitivity: str
    event_count: int
    estimated_bytes: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DataFlowReport:
    total_events: int = 0
    agents: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    edges: list[DataFlowEdge] = field(default_factory=list)
    exfiltration_alerts: list[ExfiltrationAlert] = field(default_factory=list)
    sensitivity_summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["edges"] = [e.to_dict() for e in self.edges]
        d["exfiltration_alerts"] = [a.to_dict() for a in self.exfiltration_alerts]
        return d


class DataFlowAnalyzer:
    def __init__(self, sensitivity_threshold: str = "medium") -> None:
        self.sensitivity_threshold = sensitivity_threshold

    def analyze(self, evidence_dir: str | Path) -> DataFlowReport:
        evidence_dir = Path(evidence_dir)
        events = _load_events(evidence_dir) if evidence_dir.exists() else []
        return self._build_report(events)

    def _build_report(self, events: list[dict[str, Any]]) -> DataFlowReport:
        agents: set[str] = set()
        sources: set[str] = set()
        sinks: set[str] = set()
        edge_map: dict[tuple[str, str, str], dict] = {}
        sensitivity_counts: dict[str, int] = defaultdict(int)

        for event in events:
            src_agent = event.get("agent_id", event.get("src_agent", event.get("sender", "")))
            dst_agent = event.get("dst_agent", event.get("to_agent", event.get("receiver", "")))
            resource = event.get("resource", event.get("target", event.get("destination", "")))
            data_type = event.get("data_type", event.get("type", event.get("event_type", "unknown")))
            data_size = event.get("size", event.get("bytes", event.get("content_length", 0)))
            if isinstance(data_size, str):
                try:
                    data_size = int(data_size)
                except ValueError:
                    data_size = 0

            if isinstance(src_agent, str) and src_agent:
                agents.add(src_agent)
            if isinstance(dst_agent, str) and dst_agent:
                agents.add(dst_agent)

            event_text = json.dumps(event)
            sensitivity = _classify_sensitivity(event_text)
            sensitivity_counts[sensitivity] += 1

            effective_src = src_agent or "(external)"
            effective_dst = dst_agent or resource or "(unknown)"

            if not effective_src or effective_src == effective_dst:
                if resource and _is_store(resource):
                    sinks.add(resource)
                continue

            if effective_src == "(external)" or (isinstance(effective_src, str) and _is_external(effective_src)):
                sources.add(effective_src)
            if isinstance(effective_dst, str) and _is_store(effective_dst):
                sinks.add(effective_dst)

            edge_key = (effective_src, effective_dst, data_type)
            if edge_key in edge_map:
                edge_map[edge_key]["count"] += 1
                edge_map[edge_key]["bytes"] += data_size
                if _SENSITIVITY_RANK.get(sensitivity, 0) > _SENSITIVITY_RANK.get(edge_map[edge_key]["sensitivity"], 0):
                    edge_map[edge_key]["sensitivity"] = sensitivity
            else:
                edge_map[edge_key] = {
                    "count": 1,
                    "bytes": data_size,
                    "sensitivity": sensitivity,
                }

        edges = [
            DataFlowEdge(
                source=k[0],
                target=k[1],
                data_type=k[2],
                sensitivity=v["sensitivity"],
                event_count=v["count"],
                total_bytes=v["bytes"],
            )
            for k, v in sorted(edge_map.items())
        ]

        alerts = self._detect_exfiltration(edges)

        return DataFlowReport(
            total_events=len(events),
            agents=sorted(agents),
            sources=sorted(sources),
            sinks=sorted(sinks),
            edges=edges,
            exfiltration_alerts=alerts,
            sensitivity_summary=dict(sensitivity_counts),
        )

    def _detect_exfiltration(self, edges: list[DataFlowEdge]) -> list[ExfiltrationAlert]:
        threshold_rank = _SENSITIVITY_RANK.get(self.sensitivity_threshold, 2)
        alerts: list[ExfiltrationAlert] = []

        for edge in edges:
            if not _is_external(edge.target):
                continue
            edge_rank = _SENSITIVITY_RANK.get(edge.sensitivity, 0)
            if edge_rank < threshold_rank:
                continue

            reason_parts: list[str] = []
            reason_parts.append(f"Sensitive data ({edge.sensitivity}) flowing to external destination")
            if edge.total_bytes > 1024 * 1024:
                reason_parts.append(f"large transfer ({edge.total_bytes} bytes)")
            if edge.event_count > 10:
                reason_parts.append(f"repeated transfers ({edge.event_count} events)")

            alerts.append(ExfiltrationAlert(
                source_agent=edge.source,
                destination=edge.target,
                data_type=edge.data_type,
                sensitivity=edge.sensitivity,
                event_count=edge.event_count,
                estimated_bytes=edge.total_bytes,
                reason="; ".join(reason_parts),
            ))

        return alerts


def analyze_data_flow(
    evidence_dir: str | Path,
    sensitivity_threshold: str = "medium",
) -> dict[str, Any]:
    analyzer = DataFlowAnalyzer(sensitivity_threshold=sensitivity_threshold)
    report = analyzer.analyze(evidence_dir)
    return report.to_dict()


def format_data_flow_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Data Flow Analysis ({result['total_events']} events)\n")
    lines.append(f"  Agents:  {', '.join(result['agents']) or '(none)'}")
    lines.append(f"  Sources: {', '.join(result['sources']) or '(none)'}")
    lines.append(f"  Sinks:   {', '.join(result['sinks']) or '(none)'}")

    sens = result.get("sensitivity_summary", {})
    if sens:
        parts = [f"{k}: {v}" for k, v in sorted(sens.items())]
        lines.append(f"  Sensitivity: {', '.join(parts)}")

    lines.append("")

    edges = result.get("edges", [])
    if edges:
        lines.append(f"Data Flow Edges ({len(edges)}):")
        for e in edges:
            lines.append(
                f"  {e['source']} -> {e['target']}  "
                f"[{e['data_type']}] sensitivity={e['sensitivity']}  "
                f"events={e['event_count']}  bytes={e['total_bytes']}"
            )
        lines.append("")

    alerts = result.get("exfiltration_alerts", [])
    if alerts:
        lines.append(f"Exfiltration Alerts ({len(alerts)}):")
        for a in alerts:
            lines.append(f"  [{a['sensitivity'].upper()}] {a['source_agent']} -> {a['destination']}")
            lines.append(f"    {a['reason']}")
        lines.append("")
    else:
        lines.append("No exfiltration alerts.\n")

    return "\n".join(lines) + "\n"
