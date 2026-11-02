"""Complex event filtering with compound expressions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class FilterExpr:
    """A single filter condition: field op value."""

    def __init__(self, field: str, op: str, value: str) -> None:
        self.field = field
        self.op = op
        self.value = value

    def matches(self, event: dict[str, Any]) -> bool:
        actual = _resolve_field(event, self.field)
        if actual is None:
            return self.op == "!="
        actual_str = str(actual)
        if self.op == "=":
            return actual_str == self.value
        if self.op == "!=":
            return actual_str != self.value
        if self.op == "~":
            return bool(re.search(self.value, actual_str))
        if self.op == ">":
            try:
                return float(actual_str) > float(self.value)
            except (ValueError, TypeError):
                return False
        if self.op == "<":
            try:
                return float(actual_str) < float(self.value)
            except (ValueError, TypeError):
                return False
        if self.op == ">=":
            try:
                return float(actual_str) >= float(self.value)
            except (ValueError, TypeError):
                return False
        if self.op == "<=":
            try:
                return float(actual_str) <= float(self.value)
            except (ValueError, TypeError):
                return False
        return False


def _resolve_field(event: dict[str, Any], field: str) -> Any:
    parts = field.split(".")
    current: Any = event
    for p in parts:
        if isinstance(current, dict) and p in current:
            current = current[p]
        else:
            return None
    return current


_OP_PATTERN = re.compile(r"^([a-zA-Z0-9_.]+)(!=|>=|<=|=|~|>|<)(.+)$")


def parse_expr(text: str) -> FilterExpr:
    m = _OP_PATTERN.match(text.strip())
    if not m:
        raise ValueError(f"invalid filter expression: {text!r}")
    return FilterExpr(m.group(1), m.group(2), m.group(3))


def parse_query(query: str) -> list[list[FilterExpr]]:
    """Parse a query string into DNF (OR of ANDs).

    Expressions joined by ',' (AND) form a conjunction.
    Conjunctions joined by '|' (OR) form the full query.
    Example: "agent_id=a1,type=tool_call|agent_id=a2"
    """
    clauses: list[list[FilterExpr]] = []
    for or_part in query.split("|"):
        or_part = or_part.strip()
        if not or_part:
            continue
        and_exprs: list[FilterExpr] = []
        for and_part in or_part.split(","):
            and_part = and_part.strip()
            if and_part:
                and_exprs.append(parse_expr(and_part))
        if and_exprs:
            clauses.append(and_exprs)
    return clauses


def event_matches(event: dict[str, Any], clauses: list[list[FilterExpr]]) -> bool:
    if not clauses:
        return True
    for conjunction in clauses:
        if all(expr.matches(event) for expr in conjunction):
            return True
    return False


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def filter_events(
    path: Path,
    query: str,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    events = load_events(path)
    clauses = parse_query(query)
    matched: list[dict[str, Any]] = []
    for ev in events:
        if event_matches(ev, clauses):
            matched.append(ev)
            if limit is not None and len(matched) >= limit:
                break
    return {
        "total_events": len(events),
        "matched": len(matched),
        "query": query,
        "events": matched,
    }


def format_filter_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Filter: {result['query']}")
    lines.append(f"Matched {result['matched']} of {result['total_events']} events\n")
    for i, ev in enumerate(result["events"]):
        eid = ev.get("event_id") or ev.get("id") or f"#{i}"
        etype = ev.get("event_type") or ev.get("type", "?")
        agent = ev.get("agent_id", "?")
        ts = ev.get("timestamp", "?")
        lines.append(f"  [{i}] {eid}  agent={agent}  type={etype}  ts={ts}")
    lines.append("")
    return "\n".join(lines)
