"""Tests for orbit_ir.policy detection rule engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from orbit_ir.policy import Rule, Policy, load_policy, evaluate_policy, format_policy_text


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _write_policy(path: Path, rules: list[dict], version: str = "1.0") -> None:
    data = {"version": version, "rules": rules}
    path.write_text(yaml.dump(data), encoding="utf-8")


def _make_evidence(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_jsonl(evidence / "messages.jsonl", [
        {"event_id": "m1", "timestamp": "2026-07-08T18:00:00Z", "agent_id": "a1", "recipient_agent_id": "a2"},
        {"event_id": "m2", "timestamp": "2026-07-08T18:00:07Z", "agent_id": "a2", "recipient_agent_id": None},
        {"event_id": "m3", "timestamp": "2026-07-08T18:00:14Z", "agent_id": "a1", "recipient_agent_id": "a3"},
    ])
    _write_jsonl(evidence / "transcripts.jsonl", [
        {"call_id": "c1", "agent_id": "a1", "claimed_tool": "http_get", "actual_tool": "http_get"},
        {"call_id": "c2", "agent_id": "a3", "claimed_tool": "http_post", "actual_tool": "shell_exec"},
        {"call_id": "c3", "agent_id": "a1", "claimed_tool": "db_query", "actual_tool": "db_query"},
    ])
    _write_jsonl(evidence / "control_plane.jsonl", [
        {"event_id": "cp1", "agent_id": "a1", "tool": "http_get"},
    ])
    return evidence


def test_load_policy(tmp_path: Path) -> None:
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "r1", "name": "Test Rule", "severity": "HIGH", "condition": {"field_equals": ["agent_id", "a1"]}},
    ])
    p = load_policy(pol_path)
    assert p.version == "1.0"
    assert len(p.rules) == 1
    assert p.rules[0].id == "r1"
    assert p.rules[0].severity == "HIGH"


def test_field_equals_match(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "agent_a1", "name": "Agent A1 activity", "severity": "MEDIUM",
         "condition": {"field_equals": ["agent_id", "a1"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "agent_a1"
    assert violations[0]["matched_event_count"] > 0


def test_field_contains_match(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "http_tools", "name": "HTTP tool usage", "severity": "LOW",
         "condition": {"field_contains": ["claimed_tool", "http"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert len(violations) == 1
    assert violations[0]["matched_event_count"] == 2  # http_get and http_post


def test_field_in_match(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "dangerous_tools", "name": "Dangerous tool usage", "severity": "HIGH",
         "condition": {"field_in": ["actual_tool", ["shell_exec", "admin_api"]]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert len(violations) == 1
    assert violations[0]["matched_event_count"] == 1


def test_count_gt_threshold(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "active_agent", "name": "Highly active agent", "severity": "MEDIUM",
         "condition": {"count_gt": ["agent_id", 2]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert len(violations) == 1
    assert violations[0]["matched_event_count"] >= 3  # a1 has 4+ events


def test_no_violations(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "nonexistent", "name": "No match", "severity": "HIGH",
         "condition": {"field_equals": ["agent_id", "agent_999"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert violations == []


def test_severity_filter(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "low_rule", "name": "Low", "severity": "LOW",
         "condition": {"field_equals": ["agent_id", "a1"]}},
        {"id": "high_rule", "name": "High", "severity": "HIGH",
         "condition": {"field_equals": ["agent_id", "a1"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence, severity_filter="HIGH")
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "high_rule"


def test_text_format(tmp_path: Path) -> None:
    evidence = _make_evidence(tmp_path)
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "r1", "name": "Test", "severity": "HIGH", "description": "A test rule",
         "condition": {"field_equals": ["agent_id", "a1"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    text = format_policy_text(violations)
    assert "violation" in text
    assert "r1" in text
    assert "HIGH" in text


def test_text_format_no_violations() -> None:
    text = format_policy_text([])
    assert "no violations" in text


def test_not_a_directory(tmp_path: Path) -> None:
    pol = Policy(rules=[])
    with pytest.raises(FileNotFoundError):
        evaluate_policy(pol, tmp_path / "nonexistent")


def test_empty_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    pol_path = tmp_path / "rules.yaml"
    _write_policy(pol_path, [
        {"id": "r1", "name": "Test", "severity": "HIGH",
         "condition": {"field_equals": ["agent_id", "a1"]}},
    ])
    p = load_policy(pol_path)
    violations = evaluate_policy(p, evidence)
    assert violations == []
