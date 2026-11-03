"""Anonymize evidence by replacing identifiers with consistent pseudonyms.

Uses deterministic hashing so correlations between agents, tools, and
events are preserved while real identifiers are redacted.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


_AGENT_PREFIX = "agent"
_TOOL_PREFIX = "tool"
_EVENT_PREFIX = "evt"

_IDENTIFIER_FIELDS = {
    "agent_id": _AGENT_PREFIX,
    "recipient_agent_id": _AGENT_PREFIX,
    "sender_agent_id": _AGENT_PREFIX,
    "target_agent_id": _AGENT_PREFIX,
    "claimed_tool": _TOOL_PREFIX,
    "actual_tool": _TOOL_PREFIX,
    "tool": _TOOL_PREFIX,
    "event_id": _EVENT_PREFIX,
    "call_id": _EVENT_PREFIX,
}


class Anonymizer:
    def __init__(self, salt: str = "orbit-ir") -> None:
        self._salt = salt
        self._maps: dict[str, dict[str, str]] = {}
        self._counters: dict[str, int] = {}

    def pseudonym(self, value: str, prefix: str) -> str:
        if not value:
            return value
        key = f"{prefix}:{value}"
        if key not in self._maps.setdefault(prefix, {}):
            self._counters.setdefault(prefix, 0)
            self._counters[prefix] += 1
            h = hashlib.sha256(f"{self._salt}:{value}".encode()).hexdigest()[:8]
            self._maps[prefix][key] = f"{prefix}_{self._counters[prefix]:04d}_{h}"
        return self._maps[prefix][key]

    def anonymize_row(self, row: dict) -> dict:
        out = dict(row)
        for field, prefix in _IDENTIFIER_FIELDS.items():
            if field in out and out[field] is not None:
                out[field] = self.pseudonym(str(out[field]), prefix)
        return out

    def mapping(self) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        for prefix, m in self._maps.items():
            for compound_key, pseudonym in m.items():
                original = compound_key.split(":", 1)[1] if ":" in compound_key else compound_key
                result.setdefault(prefix, {})[original] = pseudonym
        return result


def anonymize_evidence(
    evidence_dir: Path,
    output_dir: Path,
    *,
    salt: str = "orbit-ir",
    save_mapping: bool = False,
) -> dict:
    evidence_dir = Path(evidence_dir)
    output_dir = Path(output_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    anon = Anonymizer(salt=salt)

    file_stats: dict[str, int] = {}
    source_files = sorted(evidence_dir.glob("*.jsonl"))

    for src in source_files:
        rows = _read_jsonl(src)
        anonymized = [anon.anonymize_row(r) for r in rows]
        _write_jsonl(output_dir / src.name, anonymized)
        file_stats[src.name] = len(anonymized)

    mapping = anon.mapping()
    if save_mapping:
        mapping_path = output_dir / "anonymization_mapping.json"
        mapping_path.write_text(
            json.dumps(mapping, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    total_ids = sum(len(m) for m in mapping.values())
    return {
        "files_processed": len(file_stats),
        "total_records": sum(file_stats.values()),
        "identifiers_replaced": total_ids,
        "categories": {k: len(v) for k, v in mapping.items()},
        "mapping_saved": save_mapping,
    }


def format_anonymize_text(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"Anonymized {result['total_records']} records across "
                 f"{result['files_processed']} files")
    lines.append(f"  Identifiers replaced: {result['identifiers_replaced']}")
    for cat, count in sorted(result.get("categories", {}).items()):
        lines.append(f"    {cat}: {count} unique values")
    if result.get("mapping_saved"):
        lines.append("  Mapping saved to anonymization_mapping.json")
    return "\n".join(lines) + "\n"


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
