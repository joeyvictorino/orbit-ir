"""Policy enforcement engine for anomaly evidence.

Loads configurable policy rules and evaluates anomaly events against them,
reporting violations and computing a compliance score.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PolicyRule:
    id: str
    description: str
    field: str
    operator: str  # eq, ne, gt, lt, gte, lte, contains, not_contains, exists, regex
    value: Any
    severity: str = "high"


@dataclass
class Violation:
    rule_id: str
    rule_description: str
    severity: str
    event_index: int
    event_summary: str
    field_value: Any


@dataclass
class EnforcementReport:
    rules_loaded: int = 0
    events_evaluated: int = 0
    violations: list[Violation] = field(default_factory=list)
    compliance_score: float = 1.0
    violations_by_severity: dict[str, int] = field(default_factory=dict)
    rules_triggered: list[str] = field(default_factory=list)


def _load_events(evidence_dir: Path, exclude: Path | None = None) -> list[dict]:
    events: list[dict] = []
    if not evidence_dir.exists():
        return events
    for p in sorted(evidence_dir.iterdir()):
        if exclude and p.resolve() == exclude.resolve():
            continue
        if p.suffix != ".json":
            continue
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(raw, list):
            events.extend(raw)
        elif isinstance(raw, dict):
            for key in ("events", "findings", "anomalies", "records"):
                if key in raw and isinstance(raw[key], list):
                    events.extend(raw[key])
                    break
            else:
                events.append(raw)
    return events


def _load_rules(policy_path: Path) -> list[PolicyRule]:
    if not policy_path.exists():
        return []
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    rule_list = raw if isinstance(raw, list) else raw.get("rules", [])
    rules: list[PolicyRule] = []
    for r in rule_list:
        if not isinstance(r, dict):
            continue
        rid = r.get("id", f"rule_{len(rules)+1}")
        desc = r.get("description", "")
        fld = r.get("field", "")
        op = r.get("operator", "exists")
        val = r.get("value")
        sev = r.get("severity", "high")
        if fld:
            rules.append(PolicyRule(id=rid, description=desc, field=fld,
                                    operator=op, value=val, severity=sev))
    return rules


def _get_nested(event: dict, field_path: str) -> Any:
    parts = field_path.split(".")
    current: Any = event
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _check_rule(rule: PolicyRule, event: dict) -> bool:
    val = _get_nested(event, rule.field)
    op = rule.operator
    expected = rule.value

    if op == "exists":
        return val is not None
    if op == "not_exists":
        return val is None
    if val is None:
        return False

    if op == "eq":
        return val == expected
    if op == "ne":
        return val != expected
    if op == "contains":
        return isinstance(val, str) and isinstance(expected, str) and expected in val
    if op == "not_contains":
        return isinstance(val, str) and isinstance(expected, str) and expected not in val

    try:
        numeric_val = float(val) if not isinstance(val, (int, float)) else val
        numeric_exp = float(expected) if not isinstance(expected, (int, float)) else expected
    except (TypeError, ValueError):
        return False

    if op == "gt":
        return numeric_val > numeric_exp
    if op == "lt":
        return numeric_val < numeric_exp
    if op == "gte":
        return numeric_val >= numeric_exp
    if op == "lte":
        return numeric_val <= numeric_exp

    return False


def _event_summary(event: dict) -> str:
    parts: list[str] = []
    for key in ("detector", "source", "agent", "agent_id", "type"):
        if key in event:
            parts.append(f"{key}={event[key]}")
    return ", ".join(parts[:3]) if parts else "event"


def analyze(evidence_dir: Path, policy_path: Path) -> EnforcementReport:
    rules = _load_rules(policy_path)
    events = _load_events(evidence_dir, exclude=policy_path)

    report = EnforcementReport(
        rules_loaded=len(rules),
        events_evaluated=len(events),
    )

    if not rules or not events:
        return report

    triggered: set[str] = set()
    for idx, event in enumerate(events):
        for rule in rules:
            if _check_rule(rule, event):
                val = _get_nested(event, rule.field)
                report.violations.append(Violation(
                    rule_id=rule.id,
                    rule_description=rule.description,
                    severity=rule.severity,
                    event_index=idx,
                    event_summary=_event_summary(event),
                    field_value=val,
                ))
                triggered.add(rule.id)

    report.rules_triggered = sorted(triggered)

    for v in report.violations:
        report.violations_by_severity[v.severity] = (
            report.violations_by_severity.get(v.severity, 0) + 1
        )

    if events:
        violating_events = len({v.event_index for v in report.violations})
        report.compliance_score = round(
            1.0 - (violating_events / len(events)), 4
        )

    return report


def format_text(r: EnforcementReport) -> str:
    lines: list[str] = []
    lines.append("Policy Enforcement Report")
    lines.append("=" * 62)
    lines.append("")

    if r.rules_loaded == 0:
        lines.append("  No policy rules loaded.")
        return "\n".join(lines) + "\n"

    if r.events_evaluated == 0:
        lines.append("  No events to evaluate.")
        return "\n".join(lines) + "\n"

    lines.append(f"  Rules loaded:       {r.rules_loaded}")
    lines.append(f"  Events evaluated:   {r.events_evaluated}")
    lines.append(f"  Violations:         {len(r.violations)}")
    lines.append(f"  Compliance score:   {r.compliance_score:.1%}")
    lines.append("")

    if r.violations_by_severity:
        lines.append("Violations by Severity")
        lines.append("-" * 62)
        for sev in ("critical", "high", "medium", "low"):
            count = r.violations_by_severity.get(sev, 0)
            if count:
                lines.append(f"  {sev.upper():12s} {count}")
        lines.append("")

    if r.violations:
        lines.append("Violations")
        lines.append("-" * 62)
        for v in r.violations[:50]:
            lines.append(
                f"  [{v.severity.upper()}] {v.rule_id}: {v.event_summary} "
                f"({v.field_value})"
            )
        if len(r.violations) > 50:
            lines.append(f"  ... and {len(r.violations) - 50} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(r: EnforcementReport) -> str:
    return json.dumps({
        "rules_loaded": r.rules_loaded,
        "events_evaluated": r.events_evaluated,
        "violations_count": len(r.violations),
        "compliance_score": r.compliance_score,
        "violations_by_severity": r.violations_by_severity,
        "rules_triggered": r.rules_triggered,
        "violations": [
            {
                "rule_id": v.rule_id,
                "rule_description": v.rule_description,
                "severity": v.severity,
                "event_index": v.event_index,
                "event_summary": v.event_summary,
                "field_value": v.field_value,
            }
            for v in r.violations
        ],
    }, indent=2)
