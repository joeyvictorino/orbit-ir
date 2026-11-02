"""Multi-format evidence ingestion into orbit-ir standard format."""
from __future__ import annotations

import csv
import json
import re
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any


_SYSLOG_RE = re.compile(
    r"^<\d+>\d*\s*"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_SYSLOG_PLAIN_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

DEFAULT_COLUMN_MAP = {
    "timestamp": "timestamp",
    "agent": "agent",
    "action": "action",
    "target": "target",
    "severity": "severity",
}

SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}


def _make_event(
    timestamp: str,
    agent: str,
    action: str,
    target: str = "",
    severity: str = "info",
    details: dict | None = None,
    source_format: str = "unknown",
) -> dict[str, Any]:
    sev = severity.lower() if severity else "info"
    if sev not in SEVERITY_LEVELS:
        sev = "info"
    return {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "agent": agent or "unknown",
        "action": action or "",
        "target": target or "",
        "severity": sev,
        "details": details or {},
        "source_format": source_format,
    }


class EvidenceIngester:
    """Converts various log formats into orbit-ir standard evidence JSON."""

    def __init__(self, column_map: dict[str, str] | None = None):
        self.column_map = column_map or DEFAULT_COLUMN_MAP
        self.events: list[dict[str, Any]] = []
        self.errors: list[str] = []

    def ingest(self, input_path: str | Path, fmt: str = "auto", output_dir: str | Path | None = None) -> list[dict]:
        path = Path(input_path)
        if fmt == "auto":
            fmt = self._detect_format(path)

        handlers = {
            "json": self.ingest_json,
            "csv": self.ingest_csv,
            "syslog": self.ingest_syslog,
            "cloudtrail": self.ingest_cloudtrail,
        }
        handler = handlers.get(fmt)
        if not handler:
            raise ValueError(f"Unsupported format: {fmt}")

        events = handler(path)
        self.events.extend(events)

        if output_dir is not None:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            for i, event in enumerate(events):
                fname = f"event_{i:06d}.json"
                (out / fname).write_text(json.dumps(event, indent=2), encoding="utf-8")

        return events

    def ingest_json(self, path: Path) -> list[dict]:
        events = []
        files = [path] if path.is_file() else sorted(path.glob("*.json"))
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.errors.append(f"{f.name}: {exc}")
                continue
            if isinstance(data, list):
                for item in data:
                    events.append(self._normalize_json_event(item))
            elif isinstance(data, dict):
                events.append(self._normalize_json_event(data))
        return events

    def _normalize_json_event(self, raw: dict) -> dict:
        return _make_event(
            timestamp=str(raw.get("timestamp", "")),
            agent=str(raw.get("agent", raw.get("actor", ""))),
            action=str(raw.get("action", raw.get("event", raw.get("eventName", "")))),
            target=str(raw.get("target", raw.get("resource", ""))),
            severity=str(raw.get("severity", "info")),
            details={k: v for k, v in raw.items() if k not in {"timestamp", "agent", "action", "target", "severity"}},
            source_format="json",
        )

    def ingest_csv(self, path: Path) -> list[dict]:
        events = []
        text = path.read_text(encoding="utf-8")
        reader = csv.DictReader(StringIO(text))
        cmap = self.column_map
        for row in reader:
            events.append(_make_event(
                timestamp=row.get(cmap.get("timestamp", "timestamp"), ""),
                agent=row.get(cmap.get("agent", "agent"), ""),
                action=row.get(cmap.get("action", "action"), ""),
                target=row.get(cmap.get("target", "target"), ""),
                severity=row.get(cmap.get("severity", "severity"), "info"),
                details={k: v for k, v in row.items() if k not in cmap.values()},
                source_format="csv",
            ))
        return events

    def ingest_syslog(self, path: Path) -> list[dict]:
        events = []
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SYSLOG_RE.match(line) or _SYSLOG_PLAIN_RE.match(line)
            if m:
                events.append(_make_event(
                    timestamp=m.group("timestamp"),
                    agent=m.group("hostname"),
                    action=m.group("message"),
                    target=m.group("app"),
                    severity="info",
                    details={"pid": m.group("pid") or ""},
                    source_format="syslog",
                ))
            else:
                events.append(_make_event(
                    timestamp="",
                    agent="unknown",
                    action=line,
                    severity="info",
                    source_format="syslog",
                ))
        return events

    def ingest_cloudtrail(self, path: Path) -> list[dict]:
        events = []
        files = [path] if path.is_file() else sorted(path.glob("*.json"))
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.errors.append(f"{f.name}: {exc}")
                continue
            records = data.get("Records", [data] if "eventName" in data else [])
            for rec in records:
                identity = rec.get("userIdentity", {})
                agent = identity.get("userName", identity.get("arn", identity.get("type", "unknown")))
                resources = rec.get("resources", [])
                target = resources[0].get("ARN", "") if resources else rec.get("requestParameters", {}).get("bucketName", "")
                sev = "high" if rec.get("errorCode") else "info"
                events.append(_make_event(
                    timestamp=rec.get("eventTime", ""),
                    agent=str(agent),
                    action=rec.get("eventName", ""),
                    target=str(target),
                    severity=sev,
                    details={
                        "eventSource": rec.get("eventSource", ""),
                        "awsRegion": rec.get("awsRegion", ""),
                        "sourceIPAddress": rec.get("sourceIPAddress", ""),
                        "errorCode": rec.get("errorCode", ""),
                    },
                    source_format="cloudtrail",
                ))
        return events

    def _detect_format(self, path: Path) -> str:
        if path.is_dir():
            jsons = list(path.glob("*.json"))
            if jsons:
                sample = jsons[0].read_text(encoding="utf-8", errors="replace")[:500]
                if '"Records"' in sample or '"eventName"' in sample:
                    return "cloudtrail"
                return "json"
            csvs = list(path.glob("*.csv"))
            if csvs:
                return "csv"
            logs = list(path.glob("*.log")) + list(path.glob("*.syslog"))
            if logs:
                return "syslog"
            return "json"

        text = path.read_text(encoding="utf-8", errors="replace")[:1000]
        if path.suffix == ".csv":
            return "csv"
        if path.suffix in (".log", ".syslog"):
            return "syslog"
        try:
            data = json.loads(text if text.rstrip().endswith("}") or text.rstrip().endswith("]") else path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and ("Records" in data or "eventName" in data):
                return "cloudtrail"
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
        if _SYSLOG_RE.match(text.split("\n", 1)[0]) or _SYSLOG_PLAIN_RE.match(text.split("\n", 1)[0]):
            return "syslog"
        if "," in text.split("\n", 1)[0]:
            return "csv"
        return "json"

    def summary(self) -> dict:
        by_format: dict[str, int] = {}
        for e in self.events:
            fmt = e.get("source_format", "unknown")
            by_format[fmt] = by_format.get(fmt, 0) + 1
        return {
            "total_events": len(self.events),
            "by_format": by_format,
            "errors": self.errors,
        }


def format_ingest_text(summary: dict) -> str:
    lines = [f"Ingested {summary['total_events']} events"]
    for fmt, count in sorted(summary["by_format"].items()):
        lines.append(f"  {fmt}: {count}")
    if summary["errors"]:
        lines.append(f"  Errors: {len(summary['errors'])}")
        for e in summary["errors"][:5]:
            lines.append(f"    {e}")
    return "\n".join(lines)
