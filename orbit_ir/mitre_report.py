"""MITRE ATT&CK coverage report generator."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .analyzer import MITRE_TECHNIQUES

TECHNIQUE_CATALOG: dict[str, dict[str, str]] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1565": {"name": "Data Manipulation", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1119": {"name": "Automated Collection", "tactic": "Collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
}

ALL_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control",
]


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
                        pass
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                pass
    return events


def _technique_for_event(event: dict[str, Any]) -> list[str]:
    """Return technique IDs that match this event."""
    ids: list[str] = []
    mitre = event.get("mitre_technique") or event.get("technique_id")
    if isinstance(mitre, str) and mitre.startswith("T"):
        ids.append(mitre)
    for tag in event.get("tags", []):
        if isinstance(tag, str) and tag.startswith("MITRE:"):
            tid = tag.split(":", 1)[1]
            if tid.startswith("T"):
                ids.append(tid)
    detection = event.get("detection_type") or event.get("type") or ""
    mapped = MITRE_TECHNIQUES.get(detection, {})
    if mapped.get("id"):
        ids.append(mapped["id"])
    reasons = event.get("reasons") or []
    for r in reasons:
        rname = r if isinstance(r, str) else r.get("detection_type", "")
        m = MITRE_TECHNIQUES.get(rname, {})
        if m.get("id"):
            ids.append(m["id"])
    return list(dict.fromkeys(ids))


class MitreReportGenerator:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.hits: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def load_events(self, path: Path | str) -> None:
        self.events = _load_events(Path(path))

    def build_coverage(self) -> None:
        self.hits = defaultdict(list)
        for ev in self.events:
            tids = _technique_for_event(ev)
            for tid in tids:
                self.hits[tid].append(ev)

    def to_dict(self) -> dict[str, Any]:
        by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
        observed = set(self.hits.keys())
        for tid, info in TECHNIQUE_CATALOG.items():
            entry = {
                "technique_id": tid,
                "name": info["name"],
                "tactic": info["tactic"],
                "count": len(self.hits.get(tid, [])),
                "observed": tid in observed,
            }
            if self.hits.get(tid):
                entry["example_events"] = [
                    _event_summary(e) for e in self.hits[tid][:3]
                ]
            by_tactic[info["tactic"]].append(entry)

        total = len(TECHNIQUE_CATALOG)
        observed_count = sum(1 for tid in TECHNIQUE_CATALOG if tid in observed)

        tactic_stats = []
        for tactic in ALL_TACTICS:
            entries = by_tactic.get(tactic, [])
            tactic_total = len(entries)
            tactic_observed = sum(1 for e in entries if e["observed"])
            pct = (tactic_observed / tactic_total * 100) if tactic_total > 0 else 0.0
            tactic_stats.append({
                "tactic": tactic,
                "total_techniques": tactic_total,
                "observed": tactic_observed,
                "coverage_pct": round(pct, 1),
                "techniques": entries,
            })

        return {
            "total_techniques": total,
            "observed_techniques": observed_count,
            "coverage_pct": round(observed_count / total * 100, 1) if total > 0 else 0.0,
            "total_events": len(self.events),
            "tactics": tactic_stats,
        }


def _event_summary(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": ev.get("agent_id", ""),
        "timestamp": ev.get("timestamp", ""),
        "type": ev.get("type") or ev.get("detection_type", ""),
    }


def generate_mitre_report(path: Path | str) -> MitreReportGenerator:
    gen = MitreReportGenerator()
    gen.load_events(Path(path))
    gen.build_coverage()
    return gen


def format_mitre_report_text(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"MITRE ATT&CK Coverage Report")
    lines.append(f"{'=' * 40}")
    lines.append(f"Total techniques in catalog: {data['total_techniques']}")
    lines.append(f"Techniques observed:         {data['observed_techniques']}")
    lines.append(f"Overall coverage:            {data['coverage_pct']}%")
    lines.append(f"Total events analyzed:       {data['total_events']}")
    lines.append("")

    for ts in data["tactics"]:
        lines.append(f"  {ts['tactic']} ({ts['observed']}/{ts['total_techniques']} = {ts['coverage_pct']}%)")
        for tech in ts["techniques"]:
            mark = "*" if tech["observed"] else " "
            lines.append(f"    [{mark}] {tech['technique_id']}  {tech['name']:<45s} {tech['count']:>4d} events")
        lines.append("")

    return "\n".join(lines) + "\n"
