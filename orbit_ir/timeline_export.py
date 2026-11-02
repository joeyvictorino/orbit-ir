"""Multi-format timeline export for incident events."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
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


def _get_ts(ev: dict[str, Any]) -> str:
    return str(ev.get("timestamp", ev.get("time", ev.get("datetime", ""))))


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=_get_ts)


def _get_agent(ev: dict[str, Any]) -> str:
    return str(ev.get("agent_id", ev.get("agent", ev.get("source", "unknown"))))


def _get_action(ev: dict[str, Any]) -> str:
    return str(ev.get("action", ev.get("type", ev.get("event_type", ""))))


def _get_target(ev: dict[str, Any]) -> str:
    return str(ev.get("target", ev.get("destination", ev.get("resource", ""))))


def _get_severity(ev: dict[str, Any]) -> str:
    return str(ev.get("severity", ev.get("level", "info")))


def _get_details(ev: dict[str, Any]) -> str:
    return str(ev.get("details", ev.get("message", ev.get("description", ""))))


def _filter_events(
    events: list[dict[str, Any]],
    agent: str | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    result = events
    if agent:
        result = [e for e in result if _get_agent(e) == agent]
    if since:
        result = [e for e in result if _get_ts(e) >= since]
    return result


class TimelineExporter:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def load(self, path: Path, agent: str | None = None, since: str | None = None) -> list[dict[str, Any]]:
        raw = _load_events(path)
        self._events = _sort_events(_filter_events(raw, agent=agent, since=since))
        return self._events

    @property
    def events(self) -> list[dict[str, Any]]:
        return self._events

    def to_csv(self) -> str:
        buf = io.StringIO(newline="")
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["timestamp", "agent", "action", "target", "severity", "details"])
        for ev in self._events:
            writer.writerow([
                _get_ts(ev),
                _get_agent(ev),
                _get_action(ev),
                _get_target(ev),
                _get_severity(ev),
                _get_details(ev),
            ])
        return buf.getvalue()

    def to_ics(self) -> str:
        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//orbit-ir//timeline-export//EN",
        ]
        for i, ev in enumerate(self._events):
            ts_raw = _get_ts(ev)
            dt_str = _format_ics_dt(ts_raw)
            agent = _get_agent(ev)
            action = _get_action(ev)
            details = _get_details(ev)
            severity = _get_severity(ev)
            lines.append("BEGIN:VEVENT")
            lines.append(f"DTSTART:{dt_str}")
            lines.append(f"DTEND:{dt_str}")
            lines.append(f"SUMMARY:{agent} - {action}")
            lines.append(f"DESCRIPTION:Severity: {severity}\\n{details}")
            lines.append(f"UID:orbit-ir-{i}@timeline-export")
            lines.append("END:VEVENT")
        lines.append("END:VCALENDAR")
        return "\r\n".join(lines) + "\r\n"

    def to_gantt(self) -> str:
        agents: dict[str, list[dict[str, Any]]] = {}
        for ev in self._events:
            agent = _get_agent(ev)
            agents.setdefault(agent, []).append(ev)

        rows = []
        for agent, events in sorted(agents.items()):
            tasks = []
            for ev in events:
                tasks.append({
                    "name": _get_action(ev),
                    "start": _get_ts(ev),
                    "end": _get_ts(ev),
                    "severity": _get_severity(ev),
                    "target": _get_target(ev),
                })
            rows.append({"agent": agent, "tasks": tasks})

        return json.dumps({"agents": rows, "total_events": len(self._events)}, indent=2, sort_keys=True)

    def to_markdown(self) -> str:
        lines = [
            "| Timestamp | Agent | Action | Severity |",
            "|-----------|-------|--------|----------|",
        ]
        for ev in self._events:
            lines.append(
                f"| {_get_ts(ev)} | {_get_agent(ev)} | {_get_action(ev)} | {_get_severity(ev)} |"
            )
        return "\n".join(lines) + "\n"

    def export(self, fmt: str) -> str:
        dispatch = {
            "csv": self.to_csv,
            "ics": self.to_ics,
            "gantt": self.to_gantt,
            "markdown": self.to_markdown,
        }
        handler = dispatch.get(fmt)
        if handler is None:
            raise ValueError(f"Unsupported format: {fmt}")
        return handler()


def _format_ics_dt(ts: str) -> str:
    if not ts:
        return "19700101T000000Z"
    ts = ts.replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f+00:00",
                "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.strftime("%Y%m%dT%H%M%SZ")
        except ValueError:
            continue
    clean = ts.replace("-", "").replace(":", "").replace(".", "")[:15] + "Z"
    return clean


def export_timeline(
    path: Path,
    fmt: str = "csv",
    agent: str | None = None,
    since: str | None = None,
) -> str:
    exporter = TimelineExporter()
    exporter.load(path, agent=agent, since=since)
    return exporter.export(fmt)


def format_timeline_export_text(data: str) -> str:
    return data
