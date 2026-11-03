"""Detection rule engine for evaluating evidence against user-defined policies."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    condition: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    version: str = "1.0"


def load_policy(path: Path) -> Policy:
    """Load a policy from a YAML file."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"policy file must be a YAML mapping: {path}")
    version = str(raw.get("version", "1.0"))
    rules = []
    for r in raw.get("rules", []):
        rules.append(Rule(
            id=r["id"],
            name=r.get("name", r["id"]),
            description=r.get("description", ""),
            severity=r.get("severity", "medium").upper(),
            condition=r.get("condition", {}),
        ))
    return Policy(rules=rules, version=version)


def _read_all_events(evidence_dir: Path) -> list[dict]:
    """Read every JSONL file in the evidence directory into a flat list."""
    events: list[dict] = []
    for name in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl"):
        p = evidence_dir / name
        if not p.exists():
            continue
        with p.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    row["_source_file"] = name
                    events.append(row)
                except json.JSONDecodeError:
                    continue
    return events


def _check_condition(condition: dict[str, Any], events: list[dict]) -> list[dict]:
    """Evaluate a single rule condition against events, return matched events."""
    matched = []

    if "field_equals" in condition:
        field_name, expected = condition["field_equals"]
        matched = [e for e in events if str(e.get(field_name, "")) == str(expected)]

    elif "field_contains" in condition:
        field_name, substring = condition["field_contains"]
        matched = [e for e in events if substring in str(e.get(field_name, ""))]

    elif "field_in" in condition:
        field_name, values = condition["field_in"]
        value_set = set(str(v) for v in values)
        matched = [e for e in events if str(e.get(field_name, "")) in value_set]

    elif "count_gt" in condition:
        field_name, threshold = condition["count_gt"]
        counts: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            val = str(e.get(field_name, ""))
            if val:
                counts[val].append(e)
        for val, group in counts.items():
            if len(group) > threshold:
                matched.extend(group)

    return matched


def evaluate_policy(policy: Policy, evidence_dir: Path, severity_filter: str | None = None) -> list[dict]:
    """Evaluate all rules against evidence, return violations."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    events = _read_all_events(evidence_dir)
    violations = []

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_severity = severity_order.get(severity_filter.upper(), 0) if severity_filter else 0

    for rule in policy.rules:
        rule_sev = severity_order.get(rule.severity.upper(), 0)
        if rule_sev < min_severity:
            continue

        matched = _check_condition(rule.condition, events)
        if matched:
            safe_events = []
            for e in matched:
                clean = {k: v for k, v in e.items() if k != "_source_file"}
                clean["_source_file"] = e.get("_source_file", "")
                safe_events.append(clean)

            violations.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "matched_event_count": len(matched),
                "matched_events": safe_events[:10],
            })

    violations.sort(key=lambda v: -severity_order.get(v["severity"], 0))
    return violations


def format_policy_text(violations: list[dict]) -> str:
    """Human-readable policy evaluation summary."""
    if not violations:
        return "Policy evaluation: no violations found.\n"

    lines = [f"Policy evaluation: {len(violations)} violation(s) found", ""]
    for v in violations:
        lines.append(
            f"  [{v['severity']}] {v['rule_id']}: {v['rule_name']}"
            f" ({v['matched_event_count']} events matched)"
        )
        if v.get("description"):
            lines.append(f"         {v['description']}")
    lines.append("")
    return "\n".join(lines) + "\n"
