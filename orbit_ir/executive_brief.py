"""Generate concise one-page executive briefings from evidence analysis."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    elif p.is_dir():
        for f in sorted(p.iterdir()):
            if f.suffix in (".json", ".jsonl"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    return events


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


TECHNIQUE_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "credential_reuse": {"action": "Rotate all affected credentials and enforce unique credentials per agent", "owner": "Security Team"},
    "privilege_escalation": {"action": "Review and restrict agent permissions to least privilege", "owner": "Security Team"},
    "lateral_movement": {"action": "Segment agent networks and restrict inter-agent communication", "owner": "Infrastructure Team"},
    "data_exfiltration": {"action": "Implement data loss prevention controls and audit data access", "owner": "Security Team"},
    "unauthorized_access": {"action": "Review access control lists and enforce authentication", "owner": "Security Team"},
    "command_injection": {"action": "Sanitize all agent inputs and implement command allowlists", "owner": "Development Team"},
    "persistence": {"action": "Audit agent startup processes and remove unauthorized persistence mechanisms", "owner": "Operations Team"},
    "defense_evasion": {"action": "Enhance monitoring coverage and review log collection gaps", "owner": "Security Team"},
    "tool_misuse": {"action": "Restrict tool access and implement usage auditing", "owner": "Development Team"},
    "data_collection": {"action": "Review data collection scope and enforce data minimization", "owner": "Compliance Team"},
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class ExecutiveBriefGenerator:
    """Generates a one-page executive briefing from evidence."""

    def __init__(self, events: list[dict] | None = None, classification: str = "CONFIDENTIAL"):
        self._events = events or []
        self._classification = classification

    def load_events(self, path: str | Path) -> None:
        self._events = _load_events(Path(path))

    def generate(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        agents: set[str] = set()
        techniques: set[str] = set()
        severity_counts: Counter[str] = Counter()
        timestamps: list[datetime] = []
        systems: set[str] = set()
        detection_types: Counter[str] = Counter()

        for ev in self._events:
            agent = ev.get("agent_id") or ev.get("agent") or ev.get("src_agent")
            if agent:
                agents.add(agent)
            tech = ev.get("technique") or ev.get("mitre_technique") or ev.get("detection_type")
            if tech:
                techniques.add(tech)
            sev = (ev.get("severity") or ev.get("level") or "medium").lower()
            severity_counts[sev] += 1
            ts_str = ev.get("timestamp")
            if ts_str:
                ts = _parse_ts(ts_str)
                if ts:
                    timestamps.append(ts)
            resource = ev.get("resource") or ev.get("target") or ev.get("dst_agent")
            if resource:
                systems.add(resource)
            dt = ev.get("detection_type") or ev.get("event_type") or ""
            if dt:
                detection_types[dt] += 1

        timeline_hours = 0.0
        first_time = ""
        last_time = ""
        if timestamps:
            timestamps.sort()
            first_time = timestamps[0].strftime("%Y-%m-%d %H:%M UTC")
            last_time = timestamps[-1].strftime("%Y-%m-%d %H:%M UTC")
            delta = (timestamps[-1] - timestamps[0]).total_seconds()
            timeline_hours = round(delta / 3600, 2)

        overall_severity = "low"
        if severity_counts:
            best = max(severity_counts, key=lambda s: SEVERITY_ORDER.get(s, 0))
            overall_severity = best

        narrative = self._build_narrative(
            len(self._events), len(agents), len(techniques), len(systems),
            first_time, last_time, list(techniques)[:3],
        )

        top_risks = self._build_top_risks(detection_types, severity_counts, agents)
        recommended_actions = self._build_recommendations(detection_types)

        return {
            "title": "Incident Executive Briefing",
            "generated_at": now,
            "classification": self._classification,
            "key_metrics": {
                "total_events": len(self._events),
                "unique_agents": len(agents),
                "techniques_observed": len(techniques),
                "timeline_hours": timeline_hours,
                "overall_severity": overall_severity,
            },
            "narrative": narrative,
            "top_risks": top_risks[:5],
            "recommended_actions": recommended_actions[:5],
            "affected_systems": sorted(systems)[:20],
            "status": "active" if overall_severity in ("critical", "high") else "contained",
        }

    def _build_narrative(
        self, event_count: int, agent_count: int, technique_count: int,
        system_count: int, first_time: str, last_time: str, top_techniques: list[str],
    ) -> str:
        if event_count == 0:
            return "No events were observed during the analysis period."
        time_clause = ""
        if first_time and last_time and first_time != last_time:
            time_clause = f"Between {first_time} and {last_time}, "
        elif first_time:
            time_clause = f"At {first_time}, "
        tech_clause = ""
        if top_techniques:
            tech_clause = f" The predominant techniques were {', '.join(top_techniques)}."
        return (
            f"{time_clause}{agent_count} agent(s) performed {event_count} actions "
            f"across {system_count} system(s).{tech_clause}"
        )

    def _build_top_risks(
        self, detection_types: Counter, severity_counts: Counter, agents: set[str],
    ) -> list[dict[str, str]]:
        risks: list[dict[str, str]] = []
        for dt, count in detection_types.most_common(5):
            sev = "medium"
            if dt in ("credential_reuse", "privilege_escalation", "data_exfiltration"):
                sev = "critical"
            elif dt in ("lateral_movement", "command_injection", "unauthorized_access"):
                sev = "high"
            risks.append({
                "risk": dt.replace("_", " ").title(),
                "severity": sev,
                "affected": f"{count} events across {len(agents)} agents",
            })
        return risks

    def _build_recommendations(self, detection_types: Counter) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        priority = 1
        for dt, _ in detection_types.most_common(10):
            rec = TECHNIQUE_RECOMMENDATIONS.get(dt)
            if rec:
                actions.append({
                    "priority": priority,
                    "action": rec["action"],
                    "owner": rec["owner"],
                })
                priority += 1
        if not actions:
            actions.append({
                "priority": 1,
                "action": "Review all detected events and assess impact",
                "owner": "Security Team",
            })
        return actions

    def to_dict(self) -> dict[str, Any]:
        return self.generate()


def generate_executive_brief(
    path: str | Path, classification: str = "CONFIDENTIAL",
) -> ExecutiveBriefGenerator:
    gen = ExecutiveBriefGenerator(classification=classification)
    gen.load_events(path)
    return gen


def format_brief_text(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"{'=' * 60}")
    lines.append(f"  {data['title'].upper()}")
    lines.append(f"  Classification: {data['classification']}")
    lines.append(f"  Generated: {data['generated_at']}")
    lines.append(f"{'=' * 60}")
    lines.append("")

    metrics = data["key_metrics"]
    lines.append("KEY METRICS")
    lines.append(f"  Total Events:       {metrics['total_events']}")
    lines.append(f"  Unique Agents:      {metrics['unique_agents']}")
    lines.append(f"  Techniques:         {metrics['techniques_observed']}")
    lines.append(f"  Timeline Span:      {metrics['timeline_hours']} hours")
    lines.append(f"  Overall Severity:   {metrics['overall_severity'].upper()}")
    lines.append("")

    lines.append("NARRATIVE")
    lines.append(f"  {data['narrative']}")
    lines.append("")

    if data["top_risks"]:
        lines.append("TOP RISKS")
        for r in data["top_risks"]:
            lines.append(f"  [{r['severity'].upper():8s}] {r['risk']}")
            lines.append(f"             {r['affected']}")
        lines.append("")

    if data["recommended_actions"]:
        lines.append("RECOMMENDED ACTIONS")
        for a in data["recommended_actions"]:
            lines.append(f"  {a['priority']}. {a['action']}")
            lines.append(f"     Owner: {a['owner']}")
        lines.append("")

    if data["affected_systems"]:
        lines.append("AFFECTED SYSTEMS")
        for s in data["affected_systems"]:
            lines.append(f"  - {s}")
        lines.append("")

    lines.append(f"Status: {data['status'].upper()}")
    lines.append(f"{'=' * 60}")
    return "\n".join(lines) + "\n"


def format_brief_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# {data['title']}")
    lines.append(f"**Classification:** {data['classification']}  ")
    lines.append(f"**Generated:** {data['generated_at']}")
    lines.append("")

    metrics = data["key_metrics"]
    lines.append("## Key Metrics")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Events | {metrics['total_events']} |")
    lines.append(f"| Unique Agents | {metrics['unique_agents']} |")
    lines.append(f"| Techniques Observed | {metrics['techniques_observed']} |")
    lines.append(f"| Timeline Span | {metrics['timeline_hours']} hours |")
    lines.append(f"| Overall Severity | **{metrics['overall_severity'].upper()}** |")
    lines.append("")

    lines.append("## Narrative")
    lines.append(data["narrative"])
    lines.append("")

    if data["top_risks"]:
        lines.append("## Top Risks")
        for r in data["top_risks"]:
            lines.append(f"- **[{r['severity'].upper()}]** {r['risk']} — {r['affected']}")
        lines.append("")

    if data["recommended_actions"]:
        lines.append("## Recommended Actions")
        for a in data["recommended_actions"]:
            lines.append(f"{a['priority']}. {a['action']} *(Owner: {a['owner']})*")
        lines.append("")

    if data["affected_systems"]:
        lines.append("## Affected Systems")
        for s in data["affected_systems"]:
            lines.append(f"- {s}")
        lines.append("")

    lines.append(f"**Status:** {data['status'].upper()}")
    return "\n".join(lines) + "\n"
