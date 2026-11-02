"""Blast radius estimation for agent incidents."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


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


_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_RESOURCE_FIELDS = (
    "resource", "target", "destination", "file", "path", "database",
    "table", "api", "endpoint", "url", "tool_name", "service",
)

_CREDENTIAL_FIELDS = (
    "credential", "token", "api_key", "secret", "password",
)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _parse_ts(val: str | None) -> datetime | None:
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(val, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _extract_agents(event: dict[str, Any]) -> set[str]:
    agents: set[str] = set()
    for key in ("agent_id", "agent", "src_agent", "dst_agent",
                "from_agent", "to_agent", "sender", "receiver"):
        v = event.get(key)
        if isinstance(v, str) and v:
            agents.add(v)
    return agents


def _extract_resources(event: dict[str, Any]) -> set[str]:
    resources: set[str] = set()
    for key in _RESOURCE_FIELDS:
        v = event.get(key)
        if isinstance(v, str) and v:
            resources.add(v)
    text = json.dumps(event)
    for ip in _IP_RE.findall(text):
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            resources.add(f"ip:{ip}")
    return resources


def _extract_credentials(event: dict[str, Any]) -> set[str]:
    creds: set[str] = set()
    for key in _CREDENTIAL_FIELDS:
        v = event.get(key)
        if isinstance(v, str) and v:
            creds.add(f"{key}:{v[:8]}...")
    return creds


def _extract_data_flows(events: list[dict[str, Any]]) -> list[tuple[str, str]]:
    flows: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for e in events:
        src = e.get("src_agent") or e.get("from_agent") or e.get("agent_id") or e.get("sender")
        dst = e.get("dst_agent") or e.get("to_agent") or e.get("receiver")
        if src and dst and src != dst:
            pair = (str(src), str(dst))
            if pair not in seen:
                seen.add(pair)
                flows.append(pair)
        src_res = e.get("source") or e.get("from")
        dst_res = e.get("destination") or e.get("target") or e.get("to")
        if src_res and dst_res and src_res != dst_res:
            pair = (str(src_res), str(dst_res))
            if pair not in seen:
                seen.add(pair)
                flows.append(pair)
    return flows


def _compute_score(
    agent_count: int,
    resource_count: int,
    flow_count: int,
    span_seconds: float,
) -> float:
    agent_pts = min(agent_count / 5.0, 1.0) * 3.0
    resource_pts = min(resource_count / 10.0, 1.0) * 3.0
    flow_pts = min(flow_count / 8.0, 1.0) * 2.0
    span_pts = min(span_seconds / 3600.0, 1.0) * 2.0
    return round(agent_pts + resource_pts + flow_pts + span_pts, 2)


class BlastRadiusEstimator:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.affected_agents: list[str] = []
        self.affected_resources: list[str] = []
        self.affected_credentials: list[str] = []
        self.data_flows: list[tuple[str, str]] = []
        self.timeline_span_seconds: float = 0.0
        self.severity_distribution: dict[str, int] = {}
        self.blast_radius_score: float = 0.0
        self.entity_impact: dict[str, list[int]] = {}

    def load_events(self, path: Path) -> None:
        self.events = _load_events(path)

    def analyze(self) -> None:
        all_agents: set[str] = set()
        all_resources: set[str] = set()
        all_creds: set[str] = set()
        sev_counts: dict[str, int] = defaultdict(int)
        timestamps: list[datetime] = []
        entity_events: dict[str, list[int]] = defaultdict(list)

        for i, event in enumerate(self.events):
            agents = _extract_agents(event)
            all_agents.update(agents)
            for a in agents:
                entity_events[f"agent:{a}"].append(i)

            resources = _extract_resources(event)
            all_resources.update(resources)
            for r in resources:
                entity_events[f"resource:{r}"].append(i)

            creds = _extract_credentials(event)
            all_creds.update(creds)

            sev = event.get("severity", event.get("risk_level", "medium"))
            if isinstance(sev, str):
                sev_counts[sev.lower()] += 1

            ts = _parse_ts(event.get("timestamp"))
            if ts:
                timestamps.append(ts)

        self.affected_agents = sorted(all_agents)
        self.affected_resources = sorted(all_resources)
        self.affected_credentials = sorted(all_creds)
        self.severity_distribution = dict(sev_counts)
        self.data_flows = _extract_data_flows(self.events)
        self.entity_impact = {k: v for k, v in entity_events.items()}

        if len(timestamps) >= 2:
            timestamps.sort()
            self.timeline_span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()

        self.blast_radius_score = _compute_score(
            len(self.affected_agents),
            len(self.affected_resources),
            len(self.data_flows),
            self.timeline_span_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": len(self.events),
            "affected_agents": self.affected_agents,
            "affected_agent_count": len(self.affected_agents),
            "affected_resources": self.affected_resources,
            "affected_resource_count": len(self.affected_resources),
            "affected_credentials": self.affected_credentials,
            "data_flows": [{"source": s, "destination": d} for s, d in self.data_flows],
            "data_flow_count": len(self.data_flows),
            "timeline_span_seconds": self.timeline_span_seconds,
            "severity_distribution": self.severity_distribution,
            "blast_radius_score": self.blast_radius_score,
        }


def estimate_blast_radius(path: Path) -> BlastRadiusEstimator:
    estimator = BlastRadiusEstimator()
    estimator.load_events(path)
    estimator.analyze()
    return estimator


def format_blast_radius_text(data: dict[str, Any], threshold: float = 0.0) -> str:
    lines: list[str] = []
    score = data["blast_radius_score"]

    if score < threshold:
        lines.append(f"Blast radius score {score:.1f} below threshold {threshold:.1f}; no report generated.")
        return "\n".join(lines) + "\n"

    if score >= 7.0:
        level = "CRITICAL"
    elif score >= 4.0:
        level = "HIGH"
    elif score >= 2.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    lines.append(f"Blast Radius Assessment: {level} ({score:.1f}/10.0)")
    lines.append(f"  Total events analyzed: {data['total_events']}")
    lines.append("")

    lines.append(f"Affected Agents ({data['affected_agent_count']}):")
    for a in data["affected_agents"]:
        lines.append(f"  - {a}")
    lines.append("")

    lines.append(f"Affected Resources ({data['affected_resource_count']}):")
    for r in data["affected_resources"][:20]:
        lines.append(f"  - {r}")
    if data["affected_resource_count"] > 20:
        lines.append(f"  ... and {data['affected_resource_count'] - 20} more")
    lines.append("")

    if data["data_flows"]:
        lines.append(f"Data Flows ({data['data_flow_count']}):")
        for flow in data["data_flows"][:15]:
            lines.append(f"  {flow['source']} -> {flow['destination']}")
        if data["data_flow_count"] > 15:
            lines.append(f"  ... and {data['data_flow_count'] - 15} more")
        lines.append("")

    if data.get("affected_credentials"):
        lines.append(f"Affected Credentials ({len(data['affected_credentials'])}):")
        for c in data["affected_credentials"]:
            lines.append(f"  - {c}")
        lines.append("")

    lines.append(f"Timeline Span: {data['timeline_span_seconds']:.0f}s")
    lines.append("")

    if data["severity_distribution"]:
        lines.append("Severity Distribution:")
        for sev in ("critical", "high", "medium", "low"):
            count = data["severity_distribution"].get(sev, 0)
            if count:
                lines.append(f"  {sev}: {count}")
        lines.append("")

    return "\n".join(lines) + "\n"
