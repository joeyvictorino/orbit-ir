"""Behavioral profiling for agents based on evidence events."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


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


def _get_agent(ev: dict[str, Any]) -> str:
    return str(ev.get("agent_id", ev.get("agent", ev.get("source", "unknown"))))


def _get_ts(ev: dict[str, Any]) -> str:
    return str(ev.get("timestamp", ev.get("time", ev.get("datetime", ""))))


def _get_action(ev: dict[str, Any]) -> str:
    return str(ev.get("action", ev.get("type", ev.get("event_type", ""))))


def _get_target(ev: dict[str, Any]) -> str:
    return str(ev.get("target", ev.get("destination", ev.get("resource", ""))))


def _get_severity(ev: dict[str, Any]) -> str:
    return str(ev.get("severity", ev.get("level", "info"))).lower()


READ_ACTIONS = {"read", "access", "get", "fetch", "list", "query", "view", "download", "select", "search"}
CREDENTIAL_KEYWORDS = {"credential", "cred", "password", "secret", "token", "key", "auth", "api_key"}
ADMIN_KEYWORDS = {"admin", "root", "sudo", "superuser", "escalate", "privilege"}
SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _parse_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    ts_str = ts_str.replace(" ", "T")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def _assign_tags(profile: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    actions = profile.get("actions", {})
    total_actions = sum(actions.values())
    severity_dist = profile.get("severity_distribution", {})
    targets = profile.get("targets", [])

    if total_actions > 0:
        read_count = sum(actions.get(a, 0) for a in READ_ACTIONS if a in actions)
        if read_count > total_actions * 0.5:
            tags.append("data_collector")

    credential_targets = [t for t in targets if any(kw in t.lower() for kw in CREDENTIAL_KEYWORDS)]
    if len(credential_targets) >= 3:
        tags.append("credential_harvester")

    interacted_with = set()
    for t in targets:
        t_lower = t.lower()
        if "agent" in t_lower or "system" in t_lower or "service" in t_lower:
            interacted_with.add(t)
    if len(interacted_with) >= 3:
        tags.append("lateral_mover")

    has_admin = any(
        any(kw in a.lower() for kw in ADMIN_KEYWORDS)
        for a in actions
    )
    if has_admin:
        tags.append("high_privilege")

    high_sev = severity_dist.get("critical", 0) + severity_dist.get("high", 0)
    low_sev = severity_dist.get("low", 0) + severity_dist.get("info", 0)
    if high_sev > 0 and total_actions <= 5:
        tags.append("stealthy")

    if total_actions > 20 and low_sev > total_actions * 0.7:
        tags.append("noisy")

    return sorted(tags)


def _compute_risk_score(profile: dict[str, Any]) -> float:
    severity_dist = profile.get("severity_distribution", {})
    actions = profile.get("actions", {})
    targets = profile.get("targets", [])

    severity_score = 0.0
    total_events = sum(severity_dist.values()) if severity_dist else 0
    if total_events > 0:
        weighted = sum(
            SEVERITY_WEIGHTS.get(sev, 0) * count
            for sev, count in severity_dist.items()
        )
        severity_score = min(10.0, (weighted / total_events) * 2.5)

    action_diversity = min(10.0, len(actions) * 1.5)
    target_score = min(10.0, len(targets) * 1.0)

    return round(
        severity_score * 0.5 + action_diversity * 0.3 + target_score * 0.2,
        2,
    )


class AgentProfiler:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._profiles: list[dict[str, Any]] = []

    def load(self, path: Path) -> list[dict[str, Any]]:
        self._events = _load_events(path)
        return self._events

    def build_profiles(self) -> list[dict[str, Any]]:
        agents: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in self._events:
            agents[_get_agent(ev)].append(ev)

        profiles = []
        for agent_name in sorted(agents):
            events = agents[agent_name]
            actions: dict[str, int] = defaultdict(int)
            targets: set[str] = set()
            severity_dist: dict[str, int] = defaultdict(int)
            timestamps: list[str] = []

            for ev in events:
                action = _get_action(ev)
                if action:
                    actions[action] += 1
                target = _get_target(ev)
                if target:
                    targets.add(target)
                severity_dist[_get_severity(ev)] += 1
                ts = _get_ts(ev)
                if ts:
                    timestamps.append(ts)

            timestamps.sort()
            first_seen = timestamps[0] if timestamps else ""
            last_seen = timestamps[-1] if timestamps else ""

            duration = 0
            if first_seen and last_seen:
                dt_first = _parse_ts(first_seen)
                dt_last = _parse_ts(last_seen)
                if dt_first and dt_last:
                    duration = int((dt_last - dt_first).total_seconds())

            profile: dict[str, Any] = {
                "agent": agent_name,
                "event_count": len(events),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "active_duration_seconds": duration,
                "actions": dict(actions),
                "targets": sorted(targets),
                "severity_distribution": dict(severity_dist),
            }

            profile["behavioral_tags"] = _assign_tags(profile)
            profile["risk_score"] = _compute_risk_score(profile)

            risk_indicators: list[str] = []
            if len(targets) > 10:
                risk_indicators.append("accesses many resources")
            cred_targets = [t for t in targets if any(kw in t.lower() for kw in CREDENTIAL_KEYWORDS)]
            if cred_targets:
                risk_indicators.append(f"accesses {len(cred_targets)} credential(s)")
            if severity_dist.get("critical", 0) > 0:
                risk_indicators.append("has critical-severity events")
            if len(events) > 50:
                risk_indicators.append("high event rate")
            profile["risk_indicators"] = risk_indicators

            profiles.append(profile)

        self._profiles = profiles
        return profiles

    @property
    def profiles(self) -> list[dict[str, Any]]:
        return self._profiles

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_agents": len(self._profiles),
            "total_events": len(self._events),
            "profiles": self._profiles,
        }


def profile_evidence_agents(
    path: Path,
    agent: str | None = None,
    min_risk: float = 0.0,
) -> AgentProfiler:
    profiler = AgentProfiler()
    profiler.load(path)
    profiler.build_profiles()
    if agent:
        profiler._profiles = [p for p in profiler._profiles if p["agent"] == agent]
    if min_risk > 0:
        profiler._profiles = [p for p in profiler._profiles if p["risk_score"] >= min_risk]
    return profiler


def format_agent_profile_text(data: dict[str, Any]) -> str:
    profiles = data.get("profiles", [])
    if not profiles:
        return "No agent profiles found.\n"

    lines: list[str] = []
    lines.append(f"Agent Profiles ({data.get('total_agents', len(profiles))} agents, "
                 f"{data.get('total_events', 0)} events)\n")

    for p in profiles:
        lines.append(f"  Agent: {p['agent']}")
        lines.append(f"    Events: {p['event_count']}  Risk: {p['risk_score']:.1f}/10.0")
        lines.append(f"    Active: {p['first_seen']} -> {p['last_seen']} ({p['active_duration_seconds']}s)")

        if p.get("behavioral_tags"):
            lines.append(f"    Tags: {', '.join(p['behavioral_tags'])}")
        if p.get("risk_indicators"):
            lines.append(f"    Indicators: {', '.join(p['risk_indicators'])}")

        actions = p.get("actions", {})
        if actions:
            top_actions = sorted(actions.items(), key=lambda x: x[1], reverse=True)[:5]
            action_str = ", ".join(f"{a}({c})" for a, c in top_actions)
            lines.append(f"    Top actions: {action_str}")

        sev = p.get("severity_distribution", {})
        if sev:
            sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(sev.items()))
            lines.append(f"    Severity: {sev_str}")

        lines.append("")

    return "\n".join(lines)
