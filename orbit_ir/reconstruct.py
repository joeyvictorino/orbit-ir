"""Incident narrative reconstruction from evidence events."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


PHASE_KEYWORDS: dict[str, list[str]] = {
    "initial_access": [
        "initial_access", "phishing", "spearphishing", "exploit_public",
        "supply_chain", "drive_by", "valid_accounts", "login", "authenticate",
    ],
    "execution": [
        "execution", "command", "script", "run", "invoke", "spawn",
        "code_execution", "tool_call", "api_call",
    ],
    "persistence": [
        "persistence", "scheduled_task", "cron", "autostart", "registry",
        "implant", "backdoor", "hook",
    ],
    "lateral_movement": [
        "lateral_movement", "remote_service", "pivot", "proxy", "delegation",
        "pass_the_hash", "internal_spearphishing", "forwarding",
    ],
    "data_exfiltration": [
        "data_exfiltration", "exfiltration", "upload", "transfer", "steal",
        "archive", "compress", "staging",
    ],
    "privilege_escalation": [
        "privilege_escalation", "escalation", "sudo", "root", "admin",
        "token_manipulation", "elevation",
    ],
    "defense_evasion": [
        "defense_evasion", "evasion", "obfuscate", "masquerade", "disable",
        "clear_logs", "timestomp",
    ],
    "discovery": [
        "discovery", "scan", "enumerate", "list", "query", "reconnaissance",
        "recon",
    ],
    "command_and_control": [
        "command_and_control", "c2", "beacon", "callback", "tunnel",
        "channel",
    ],
}

PHASE_ORDER = [
    "initial_access",
    "discovery",
    "privilege_escalation",
    "execution",
    "persistence",
    "defense_evasion",
    "lateral_movement",
    "command_and_control",
    "data_exfiltration",
]


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        for f in sorted(path.glob("*.json")):
            if f.name.endswith(".jsonl"):
                continue
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
    else:
        text = path.read_text()
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
                    events.append(json.loads(line))
    return events


def _assign_phase(event: dict[str, Any]) -> str:
    ev_type = event.get("type", "").lower()
    action = event.get("action", "").lower()
    techniques = event.get("techniques", [])
    if isinstance(techniques, str):
        techniques = [techniques]
    tags = event.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]

    searchable = [ev_type, action] + [t.lower() for t in techniques] + [t.lower() for t in tags]
    text = " ".join(searchable)

    for phase in PHASE_ORDER:
        keywords = PHASE_KEYWORDS[phase]
        for kw in keywords:
            if kw in text:
                return phase

    return "execution"


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(ev: dict[str, Any]) -> str:
        ts = ev.get("timestamp", "")
        if not ts:
            ts = ev.get("time", ev.get("datetime", ""))
        return str(ts)

    return sorted(events, key=sort_key)


def _event_narrative_line(event: dict[str, Any]) -> str:
    ts = event.get("timestamp", event.get("time", "unknown time"))
    agent = event.get("agent_id", event.get("agent", event.get("source", "unknown agent")))
    action = event.get("action", event.get("type", "performed an action"))
    target = event.get("target", event.get("destination", event.get("resource", "")))
    outcome = event.get("outcome", event.get("result", event.get("status", "")))

    line = f"At {ts}, {agent} {action}"
    if target:
        line += f" on {target}"
    if outcome:
        line += f". This resulted in {outcome}"
    line += "."
    return line


class IncidentReconstructor:
    def __init__(self) -> None:
        self._raw_events: list[dict[str, Any]] = []
        self._timeline: list[dict[str, Any]] = []
        self._phases: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def load_events(self, path: Path) -> list[dict[str, Any]]:
        self._raw_events = _load_events(path)
        return self._raw_events

    def build_timeline(self) -> list[dict[str, Any]]:
        self._timeline = _sort_events(self._raw_events)
        return self._timeline

    def assign_phases(self) -> dict[str, list[dict[str, Any]]]:
        self._phases = defaultdict(list)
        for ev in self._timeline:
            phase = _assign_phase(ev)
            ev_with_phase = {**ev, "_phase": phase}
            self._phases[phase].append(ev_with_phase)
        return dict(self._phases)

    def generate_narrative(self) -> str:
        if not self._timeline:
            return "No events to reconstruct."

        lines: list[str] = []
        lines.append("=== Incident Reconstruction ===\n")

        ordered_phases = [p for p in PHASE_ORDER if p in self._phases]
        for remaining in self._phases:
            if remaining not in ordered_phases:
                ordered_phases.append(remaining)

        for phase in ordered_phases:
            events = self._phases[phase]
            phase_label = phase.replace("_", " ").title()
            lines.append(f"\n--- Phase: {phase_label} ({len(events)} events) ---\n")
            for ev in events:
                lines.append(f"  {_event_narrative_line(ev)}")

        total_agents = set()
        for ev in self._timeline:
            agent = ev.get("agent_id", ev.get("agent", ev.get("source", "")))
            if agent:
                total_agents.add(agent)

        lines.append(f"\n--- Summary ---")
        lines.append(f"  Total events: {len(self._timeline)}")
        lines.append(f"  Phases observed: {len(ordered_phases)}")
        lines.append(f"  Agents involved: {len(total_agents)}")
        if self._timeline:
            first_ts = self._timeline[0].get("timestamp", self._timeline[0].get("time", "?"))
            last_ts = self._timeline[-1].get("timestamp", self._timeline[-1].get("time", "?"))
            lines.append(f"  Time span: {first_ts} -> {last_ts}")
        lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        ordered_phases = [p for p in PHASE_ORDER if p in self._phases]
        for remaining in self._phases:
            if remaining not in ordered_phases:
                ordered_phases.append(remaining)

        total_agents = set()
        for ev in self._timeline:
            agent = ev.get("agent_id", ev.get("agent", ev.get("source", "")))
            if agent:
                total_agents.add(agent)

        phase_list = []
        for phase in ordered_phases:
            events = self._phases[phase]
            phase_list.append({
                "name": phase,
                "event_count": len(events),
                "events": [{k: v for k, v in ev.items() if k != "_phase"} for ev in events],
            })

        return {
            "total_events": len(self._timeline),
            "phases_observed": len(ordered_phases),
            "agents_involved": sorted(total_agents),
            "phases": phase_list,
            "timeline": self._timeline,
        }


def reconstruct_incident(path: Path) -> IncidentReconstructor:
    r = IncidentReconstructor()
    r.load_events(path)
    r.build_timeline()
    r.assign_phases()
    return r


def format_reconstruct_text(reconstructor: IncidentReconstructor) -> str:
    return reconstructor.generate_narrative()
