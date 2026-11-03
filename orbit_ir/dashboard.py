"""Generate a standalone HTML dashboard from evidence analysis."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .stats import evidence_stats
from .correlate import correlate_events


_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_dashboard(
    evidence_dir: Path,
    output_path: Path,
    title: str = "Orbit-IR Dashboard",
) -> dict:
    evidence_dir = Path(evidence_dir)
    output_path = Path(output_path)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    stats = evidence_stats(evidence_dir)

    findings: list[dict] = []
    try:
        corr = correlate_events(evidence_dir, time_window_seconds=5)
        findings = corr.get("correlations", [])
    except Exception:
        pass

    analysis_findings = _load_findings(evidence_dir)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in analysis_findings:
        sev = f.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    agent_activity = _compute_agent_activity(evidence_dir)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    page = _render_html(
        title=title,
        generated_at=generated_at,
        evidence_path=str(evidence_dir),
        stats=stats,
        severity_counts=severity_counts,
        findings=analysis_findings,
        agent_activity=agent_activity,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(page, encoding="utf-8")

    return {
        "output": str(output_path),
        "agents": stats["agents"],
        "messages": stats["messages"],
        "transcripts": stats["transcripts"],
        "findings": len(analysis_findings),
        "generated_at": generated_at,
    }


def _load_findings(evidence_dir: Path) -> list[dict]:
    for candidate in [
        evidence_dir / "findings.json",
        evidence_dir.parent / "results" / "findings.json",
    ]:
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return []


def _compute_agent_activity(evidence_dir: Path) -> list[dict]:
    agent_msgs: dict[str, int] = {}
    agent_tools: dict[str, set[str]] = {}

    msg_path = evidence_dir / "messages.jsonl"
    if msg_path.exists():
        for line in msg_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = row.get("agent_id", "unknown")
            agent_msgs[aid] = agent_msgs.get(aid, 0) + 1

    tx_path = evidence_dir / "transcripts.jsonl"
    if tx_path.exists():
        for line in tx_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = row.get("agent_id", "unknown")
            tool = row.get("claimed_tool")
            if tool:
                agent_tools.setdefault(aid, set()).add(tool)

    all_agents = sorted(set(agent_msgs) | set(agent_tools))
    return [
        {
            "agent_id": a,
            "messages": agent_msgs.get(a, 0),
            "tools": sorted(agent_tools.get(a, set())),
            "tool_count": len(agent_tools.get(a, set())),
        }
        for a in all_agents
    ]


def _render_html(
    *,
    title: str,
    generated_at: str,
    evidence_path: str,
    stats: dict,
    severity_counts: dict[str, int],
    findings: list[dict],
    agent_activity: list[dict],
) -> str:
    esc = html.escape

    total_findings = sum(severity_counts.values())
    max_sev = max(severity_counts.values()) if total_findings > 0 else 1

    severity_bars = ""
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts[sev]
        pct = (count / max_sev * 100) if max_sev > 0 else 0
        color = _SEVERITY_COLORS[sev]
        severity_bars += f"""
        <div style="display:flex;align-items:center;margin-bottom:6px;">
          <span style="width:70px;font-size:13px;text-transform:uppercase;color:{color};font-weight:600;">{sev}</span>
          <div style="flex:1;background:var(--bar-bg);border-radius:4px;height:22px;margin-right:10px;">
            <div style="width:{pct:.1f}%;background:{color};height:100%;border-radius:4px;min-width:{2 if count > 0 else 0}px;"></div>
          </div>
          <span style="font-size:14px;font-weight:600;width:30px;text-align:right;">{count}</span>
        </div>"""

    time_range_str = ""
    tr = stats.get("time_range", {})
    if tr:
        time_range_str = f"{esc(tr.get('earliest', '?'))} &mdash; {esc(tr.get('latest', '?'))}"

    findings_rows = ""
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "low").lower(), 9),
    )
    for f in sorted_findings[:200]:
        sev = f.get("severity", "low").lower()
        color = _SEVERITY_COLORS.get(sev, "#888")
        desc = esc(f.get("description", f.get("detection_type", "—")))
        agent = esc(f.get("agent_id", "—"))
        det_type = esc(f.get("detection_type", "—"))
        evidence_list = f.get("reasons", f.get("evidence", []))
        evidence_str = esc("; ".join(str(e) for e in evidence_list[:3])) if evidence_list else "—"
        findings_rows += f"""
        <tr>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;text-transform:uppercase;">{sev}</span></td>
          <td>{det_type}</td>
          <td>{agent}</td>
          <td>{desc}</td>
          <td style="font-size:12px;color:var(--muted);">{evidence_str}</td>
        </tr>"""

    agent_rows = ""
    for a in agent_activity:
        tools_str = esc(", ".join(a["tools"][:5]))
        if len(a["tools"]) > 5:
            tools_str += f" (+{len(a['tools']) - 5} more)"
        agent_rows += f"""
        <tr>
          <td><code>{esc(a['agent_id'])}</code></td>
          <td style="text-align:right;">{a['messages']}</td>
          <td style="text-align:right;">{a['tool_count']}</td>
          <td style="font-size:12px;">{tools_str}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #1a1a2e; --card-bg: #f8f9fa; --border: #e2e8f0;
  --bar-bg: #e2e8f0; --muted: #64748b; --header-bg: #1e293b; --header-fg: #f1f5f9;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0f172a; --fg: #e2e8f0; --card-bg: #1e293b; --border: #334155;
    --bar-bg: #334155; --muted: #94a3b8; --header-bg: #020617; --header-fg: #f1f5f9;
  }}
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:var(--bg); color:var(--fg); line-height:1.5; }}
.header {{ background:var(--header-bg); color:var(--header-fg); padding:24px; }}
.header h1 {{ font-size:24px; margin-bottom:4px; }}
.header .meta {{ font-size:13px; opacity:0.7; }}
.container {{ max-width:1200px; margin:0 auto; padding:16px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px, 1fr)); gap:12px; margin:20px 0; }}
.card {{ background:var(--card-bg); border:1px solid var(--border); border-radius:8px; padding:16px; text-align:center; }}
.card .value {{ font-size:28px; font-weight:700; }}
.card .label {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; }}
.section {{ margin:24px 0; }}
.section h2 {{ font-size:18px; margin-bottom:12px; padding-bottom:6px; border-bottom:2px solid var(--border); }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th, td {{ padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
th {{ font-weight:600; font-size:12px; text-transform:uppercase; color:var(--muted); }}
tr:hover {{ background:var(--card-bg); }}
code {{ font-size:13px; }}
.footer {{ margin-top:32px; padding:16px 0; border-top:1px solid var(--border); font-size:12px; color:var(--muted); text-align:center; }}
</style>
</head>
<body>
<div class="header">
  <h1>{esc(title)}</h1>
  <div class="meta">Generated {esc(generated_at)} &middot; Evidence: {esc(evidence_path)}</div>
</div>
<div class="container">

<div class="cards">
  <div class="card"><div class="value">{stats['agents']}</div><div class="label">Agents</div></div>
  <div class="card"><div class="value">{stats['messages']}</div><div class="label">Messages</div></div>
  <div class="card"><div class="value">{stats['transcripts']}</div><div class="label">Transcripts</div></div>
  <div class="card"><div class="value">{total_findings}</div><div class="label">Findings</div></div>
  <div class="card"><div class="value">{len(stats.get('unique_tools', []))}</div><div class="label">Unique Tools</div></div>
</div>

{"<div class='section'><h2>Time Range</h2><p>" + time_range_str + "</p></div>" if time_range_str else ""}

<div class="section">
  <h2>Severity Breakdown</h2>
  {severity_bars}
</div>

<div class="section">
  <h2>Findings ({total_findings})</h2>
  {"<table><thead><tr><th>Severity</th><th>Type</th><th>Agent</th><th>Description</th><th>Evidence</th></tr></thead><tbody>" + findings_rows + "</tbody></table>" if findings_rows else "<p style='color:var(--muted);'>No findings.</p>"}
</div>

<div class="section">
  <h2>Agent Activity ({len(agent_activity)} agents)</h2>
  {"<table><thead><tr><th>Agent</th><th style='text-align:right;'>Messages</th><th style='text-align:right;'>Tools</th><th>Tool Names</th></tr></thead><tbody>" + agent_rows + "</tbody></table>" if agent_rows else "<p style='color:var(--muted);'>No agent activity data.</p>"}
</div>

<div class="footer">Generated by orbit-ir</div>
</div>
</body>
</html>
"""
