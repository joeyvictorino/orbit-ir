"""Customizable report generation with built-in and user-defined templates."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BUILTIN_TEMPLATES = {
    "full": """\
# {{title}}

Generated: {{generated_at}}

## Executive Summary

Total events: {{total_events}}
Unique agents: {{unique_agents}}

{{severity_summary}}

## Techniques Observed

{{technique_summary}}

## Timeline

{{timeline_summary}}

## Key Findings

{{top_findings}}

## Affected Systems

{{affected_systems}}

## Recommendations

{{recommendations}}
""",
    "brief": """\
# {{title}} — Executive Brief

Generated: {{generated_at}}

Events: {{total_events}} | Agents: {{unique_agents}}

{{severity_summary}}

**Top Findings:** {{top_findings}}

**Recommended Actions:** {{recommendations}}
""",
    "technical": """\
# {{title}} — Technical Report

Generated: {{generated_at}}

## Findings

{{top_findings}}

## Techniques

{{technique_summary}}

## Timeline

{{timeline_summary}}

## Affected Systems

{{affected_systems}}
""",
    "compliance": """\
# {{title}} — Compliance Report

Generated: {{generated_at}}

## Overview

Total events: {{total_events}}
Unique agents: {{unique_agents}}

## Severity Distribution

{{severity_summary}}

## Technique Coverage

{{technique_summary}}

## Affected Systems

{{affected_systems}}

## Recommendations

{{recommendations}}
""",
}


def list_templates() -> list[dict[str, str]]:
    descs = {
        "full": "Complete report with all sections",
        "brief": "Executive summary only",
        "technical": "Findings and timeline focus",
        "compliance": "Framework mapping focus",
    }
    return [{"name": n, "description": descs.get(n, "")} for n in BUILTIN_TEMPLATES]


def show_template(name: str) -> str | None:
    return BUILTIN_TEMPLATES.get(name)


class TemplateReporter:
    """Renders reports from templates filled with evidence analysis data."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def load_events(self, evidence_dir: str | Path) -> None:
        path = Path(evidence_dir)
        self.events = []
        if path.is_file():
            self._load_file(path)
        elif path.is_dir():
            for f in sorted(path.glob("*.json")):
                self._load_file(f)

    def _load_file(self, f: Path) -> None:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if isinstance(data, list):
            self.events.extend(data)
        elif isinstance(data, dict):
            self.events.append(data)

    def build_variables(self, title: str = "Incident Report") -> dict[str, str]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        agents = set()
        severities: dict[str, int] = {}
        techniques: dict[str, int] = {}
        systems: set[str] = set()
        timestamps: list[str] = []

        for ev in self.events:
            a = ev.get("agent", "")
            if a:
                agents.add(a)
            sev = ev.get("severity", "info")
            severities[sev] = severities.get(sev, 0) + 1
            for t in ev.get("techniques", []):
                tid = t if isinstance(t, str) else t.get("id", str(t))
                techniques[tid] = techniques.get(tid, 0) + 1
            target = ev.get("target", "")
            if target:
                systems.add(target)
            ts = ev.get("timestamp", "")
            if ts:
                timestamps.append(ts)

        sev_lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = severities.get(sev, 0)
            if cnt:
                sev_lines.append(f"- {sev.capitalize()}: {cnt}")
        severity_summary = "\n".join(sev_lines) if sev_lines else "No events."

        tech_lines = []
        for tid, cnt in sorted(techniques.items(), key=lambda x: -x[1])[:10]:
            tech_lines.append(f"- {tid}: {cnt} occurrences")
        technique_summary = "\n".join(tech_lines) if tech_lines else "No techniques identified."

        sorted_ts = sorted(timestamps) if timestamps else []
        if sorted_ts:
            timeline_summary = f"First event: {sorted_ts[0]}\nLast event: {sorted_ts[-1]}\nSpan: {len(sorted_ts)} events"
        else:
            timeline_summary = "No timeline data."

        findings = []
        crit_high = [e for e in self.events if e.get("severity") in ("critical", "high")]
        for ev in crit_high[:10]:
            action = ev.get("action", "unknown action")
            agent = ev.get("agent", "unknown")
            sev = ev.get("severity", "info")
            findings.append(f"- [{sev.upper()}] {agent}: {action}")
        top_findings = "\n".join(findings) if findings else "No critical or high severity findings."

        affected = sorted(systems)[:20]
        affected_systems = "\n".join(f"- {s}" for s in affected) if affected else "No systems identified."

        recommendations = self._generate_recommendations(severities, techniques)

        return {
            "title": title,
            "generated_at": now,
            "total_events": str(len(self.events)),
            "unique_agents": str(len(agents)),
            "severity_summary": severity_summary,
            "technique_summary": technique_summary,
            "timeline_summary": timeline_summary,
            "top_findings": top_findings,
            "affected_systems": affected_systems,
            "recommendations": recommendations,
        }

    def _generate_recommendations(self, severities: dict, techniques: dict) -> str:
        recs = []
        if severities.get("critical", 0) > 0:
            recs.append("- URGENT: Investigate and contain critical severity events immediately")
        if severities.get("high", 0) > 0:
            recs.append("- Review high severity events for potential active threats")
        tech_names = set(techniques.keys())
        if any("escalat" in t.lower() for t in tech_names):
            recs.append("- Audit privilege escalation paths and restrict agent permissions")
        if any("lateral" in t.lower() for t in tech_names):
            recs.append("- Segment agent networks to limit lateral movement")
        if any("exfil" in t.lower() for t in tech_names):
            recs.append("- Monitor and restrict outbound data transfers")
        if any("credential" in t.lower() or "cred" in t.lower() for t in tech_names):
            recs.append("- Rotate all potentially compromised credentials")
        if not recs:
            recs.append("- Continue routine monitoring")
            recs.append("- Review agent access policies periodically")
        return "\n".join(recs)

    def render(self, template_name_or_path: str, evidence_dir: str | Path, title: str = "Incident Report") -> str:
        self.load_events(evidence_dir)
        variables = self.build_variables(title=title)

        if template_name_or_path in BUILTIN_TEMPLATES:
            tmpl = BUILTIN_TEMPLATES[template_name_or_path]
        else:
            tpath = Path(template_name_or_path)
            if tpath.is_file():
                tmpl = tpath.read_text(encoding="utf-8")
            else:
                raise ValueError(f"Unknown template: {template_name_or_path}")

        return self._fill(tmpl, variables)

    def _fill(self, template: str, variables: dict[str, str]) -> str:
        def replacer(m: re.Match) -> str:
            key = m.group(1)
            return variables.get(key, m.group(0))
        return re.sub(r"\{\{(\w+)\}\}", replacer, template)

    def to_html(self, markdown_text: str) -> str:
        lines = markdown_text.split("\n")
        html_lines = ["<!DOCTYPE html>", "<html><head><meta charset='utf-8'>", "<style>body{font-family:sans-serif;max-width:800px;margin:0 auto;padding:20px;}",
                       "h1{border-bottom:2px solid #333;} h2{color:#555;} li{margin:4px 0;}</style>", "</head><body>"]
        in_list = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# "):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<h1>{_esc(stripped[2:])}</h1>")
            elif stripped.startswith("## "):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<h2>{_esc(stripped[3:])}</h2>")
            elif stripped.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{_esc(stripped[2:])}</li>")
            elif stripped.startswith("**") and stripped.endswith("**"):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<p><strong>{_esc(stripped[2:-2])}</strong></p>")
            elif stripped:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<p>{_esc(stripped)}</p>")
        if in_list:
            html_lines.append("</ul>")
        html_lines.append("</body></html>")
        return "\n".join(html_lines)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_template_list(templates: list[dict]) -> str:
    lines = ["Available templates:"]
    for t in templates:
        lines.append(f"  {t['name']:12s} {t['description']}")
    return "\n".join(lines)
