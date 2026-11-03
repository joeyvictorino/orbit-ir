"""Indicator of Compromise (IOC) extraction from evidence events."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}\b"
)

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|dev|ai|info|biz|co|xyz|cloud|app|edu|gov|mil)\b"
)

MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

URL_RE = re.compile(r"https?://[^\s\"'<>\])}]+")

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

FILE_PATH_RE = re.compile(
    r"(?:/(?:etc|tmp|var|usr|home|opt|root|proc|dev|sys|bin|sbin|mnt|media)"
    r"(?:/[^\s\"'<>|;&#]+)+)"
    r"|"
    r"(?:[A-Z]:\\(?:[^\s\"'<>|;&#]+\\?)+)"
)

COMMAND_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|python|perl|bash|sh|"
    r"powershell|cmd|chmod|chown|sudo|nmap|nikto|sqlmap|hydra|"
    r"msfconsole|metasploit|gobuster|ffuf|dirb|hashcat|john)\b[^\n]*"
)

IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": IPV4_RE,
    "ipv6": IPV6_RE,
    "domain": DOMAIN_RE,
    "md5": MD5_RE,
    "sha1": SHA1_RE,
    "sha256": SHA256_RE,
    "url": URL_RE,
    "email": EMAIL_RE,
    "file_path": FILE_PATH_RE,
    "command": COMMAND_RE,
}

HASH_TYPES = {"md5", "sha1", "sha256"}

# Words that look like hashes but aren't meaningful IOCs
FALSE_POSITIVE_HASHES = {
    "00000000000000000000000000000000",
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file MD5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # empty file SHA1
}


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


def _flatten_values(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_values(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_values(v) for v in obj)
    return str(obj)


class IOCExtractor:
    def __init__(self) -> None:
        self._iocs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def extract_from_event(
        self, event: dict[str, Any], source_id: str = "",
    ) -> list[dict[str, Any]]:
        text = _flatten_values(event)
        ts = event.get("timestamp", event.get("time", ""))
        found: list[dict[str, Any]] = []

        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).strip().rstrip("/\\")
                if not value:
                    continue
                if ioc_type in HASH_TYPES and value.lower() in FALSE_POSITIVE_HASHES:
                    continue

                if value in self._iocs[ioc_type]:
                    entry = self._iocs[ioc_type][value]
                    entry["count"] += 1
                    if source_id and source_id not in entry["source_events"]:
                        entry["source_events"].append(source_id)
                else:
                    entry = {
                        "type": ioc_type,
                        "value": value,
                        "source_events": [source_id] if source_id else [],
                        "first_seen": str(ts),
                        "count": 1,
                    }
                    self._iocs[ioc_type][value] = entry
                found.append(entry)

        return found

    def extract_from_directory(self, path: Path) -> dict[str, list[dict[str, Any]]]:
        events = _load_events(path)
        for i, ev in enumerate(events):
            event_id = ev.get("event_id", ev.get("id", f"event_{i}"))
            self.extract_from_event(ev, source_id=str(event_id))
        return self.to_dict()

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for ioc_type in sorted(self._iocs.keys()):
            entries = sorted(
                self._iocs[ioc_type].values(),
                key=lambda e: e["count"],
                reverse=True,
            )
            result[ioc_type] = [
                {
                    "type": e["type"],
                    "value": e["value"],
                    "source_event": e["source_events"][0] if e["source_events"] else "",
                    "first_seen": e["first_seen"],
                    "count": e["count"],
                }
                for e in entries
            ]
        return result


def extract_iocs(path: Path) -> IOCExtractor:
    extractor = IOCExtractor()
    extractor.extract_from_directory(path)
    return extractor


def format_ioc_text(
    data: dict[str, list[dict[str, Any]]],
    type_filter: str | None = None,
    min_count: int = 1,
) -> str:
    lines: list[str] = []
    lines.append("=== Indicators of Compromise ===\n")

    total = 0
    for ioc_type in sorted(data.keys()):
        if type_filter and ioc_type != type_filter:
            continue
        entries = [e for e in data[ioc_type] if e["count"] >= min_count]
        if not entries:
            continue
        total += len(entries)
        label = ioc_type.upper().replace("_", " ")
        lines.append(f"\n--- {label} ({len(entries)} unique) ---\n")
        for e in entries:
            lines.append(
                f"  {e['value']:<60s}  count={e['count']:<4d}  first_seen={e['first_seen']}"
            )

    lines.append(f"\n--- Summary ---")
    lines.append(f"  Total unique IOCs: {total}")
    types_shown = sum(
        1 for t in data
        if (not type_filter or t == type_filter)
        and any(e["count"] >= min_count for e in data[t])
    )
    lines.append(f"  IOC types: {types_shown}")
    lines.append("")
    return "\n".join(lines)
