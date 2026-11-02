"""Tests for remediation suggestion generator."""

import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.remediate_ir import (
    RemediationGenerator,
    generate_remediations,
    format_remediate_text,
    REMEDIATION_KB,
    _classify_event,
    _SEVERITY_WEIGHT,
)


def _write_events(tmp: Path, events: list[dict]) -> Path:
    p = tmp / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp


def test_remediation_kb_has_entries():
    assert len(REMEDIATION_KB) >= 10


def test_remediation_kb_structure():
    for key, entry in REMEDIATION_KB.items():
        assert "title" in entry
        assert "severity" in entry
        assert "steps" in entry
        assert "references" in entry
        assert len(entry["steps"]) >= 2
        assert entry["severity"] in ("critical", "high", "medium", "low")


def test_classify_event_by_detection_type():
    event = {"detection_type": "tool-name-mismatch", "agent_id": "a1"}
    types = _classify_event(event)
    assert "tool_name_mismatch" in types


def test_classify_event_by_keywords():
    event = {"message": "credential reuse detected between agents"}
    types = _classify_event(event)
    assert "credential_reuse" in types


def test_classify_event_privilege_escalation():
    event = {"action": "privilege escalation to root"}
    types = _classify_event(event)
    assert "privilege_escalation" in types


def test_classify_event_empty():
    assert _classify_event({}) == set()


def test_classify_event_no_match():
    event = {"message": "normal operation completed"}
    types = _classify_event(event)
    # "normal" doesn't match any detection keywords
    assert "credential_reuse" not in types
    assert "privilege_escalation" not in types


def test_generator_empty_dir():
    with tempfile.TemporaryDirectory() as tmp:
        gen = generate_remediations(Path(tmp))
        assert gen.to_dict()["suggestion_count"] == 0


def test_generator_with_credential_reuse():
    events = [
        {"agent_id": "a1", "detection_type": "credential_reuse"},
        {"agent_id": "a2", "detection_type": "credential_reuse"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp))
        d = gen.to_dict()
        assert d["suggestion_count"] >= 1
        cred = [s for s in d["suggestions"] if s["detection_type"] == "credential_reuse"]
        assert len(cred) == 1
        assert set(cred[0]["affected_agents"]) == {"a1", "a2"}


def test_generator_priority_ordering():
    events = [
        {"detection_type": "unbacked_completion", "agent_id": "a1"},  # medium
        {"detection_type": "command_injection", "agent_id": "a2"},    # critical
        {"detection_type": "lateral_movement", "agent_id": "a3"},     # high
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp))
        suggestions = gen.to_dict()["suggestions"]
        assert len(suggestions) >= 2
        priorities = [s["priority"] for s in suggestions]
        assert priorities == sorted(priorities, reverse=True)


def test_generator_severity_filter():
    events = [
        {"detection_type": "unbacked_completion", "agent_id": "a1"},  # medium
        {"detection_type": "command_injection", "agent_id": "a2"},    # critical
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp), severity_filter="high")
        suggestions = gen.to_dict()["suggestions"]
        for s in suggestions:
            assert _SEVERITY_WEIGHT[s["severity"]] >= _SEVERITY_WEIGHT["high"]


def test_generator_to_dict_structure():
    events = [{"detection_type": "persistence", "agent_id": "a1"}]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp))
        d = gen.to_dict()
        assert "total_events" in d
        assert "suggestion_count" in d
        assert "suggestions" in d
        assert d["total_events"] == 1


def test_format_text_empty():
    data = {"total_events": 0, "suggestion_count": 0, "suggestions": []}
    text = format_remediate_text(data)
    assert "No actionable remediations" in text


def test_format_text_with_suggestions():
    data = {
        "total_events": 10,
        "suggestion_count": 1,
        "suggestions": [{
            "detection_type": "credential_reuse",
            "title": "Credential Reuse Detected",
            "severity": "high",
            "event_count": 5,
            "affected_agents": ["a1", "a2"],
            "steps": ["Rotate credentials", "Implement unique credentials"],
            "references": ["CIS 5.2"],
            "priority": 6,
        }],
    }
    text = format_remediate_text(data)
    assert "HIGH" in text
    assert "Credential Reuse" in text
    assert "a1" in text
    assert "Rotate credentials" in text
    assert "CIS 5.2" in text


def test_generator_keyword_detection():
    events = [
        {"message": "agent performed lateral movement to new subnet", "agent_id": "a1"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp))
        types = [s["detection_type"] for s in gen.to_dict()["suggestions"]]
        assert "lateral_movement" in types


def test_generator_multiple_detections():
    events = [
        {"detection_type": "credential_reuse", "agent_id": "a1"},
        {"detection_type": "privilege_escalation", "agent_id": "a1"},
        {"detection_type": "data_exfiltration", "agent_id": "a2"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp))
        d = gen.to_dict()
        assert d["suggestion_count"] >= 3


def test_generator_single_json_file():
    events = [
        {"detection_type": "defense_evasion", "agent_id": "a1"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "findings.json"
        p.write_text(json.dumps(events), encoding="utf-8")
        gen = generate_remediations(p)
        assert gen.to_dict()["suggestion_count"] >= 1


def test_severity_filter_critical_only():
    events = [
        {"detection_type": "unbacked_completion", "agent_id": "a1"},  # medium
        {"detection_type": "privilege_escalation", "agent_id": "a2"},  # critical
        {"detection_type": "lateral_movement", "agent_id": "a3"},      # high
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_events(Path(tmp), events)
        gen = generate_remediations(Path(tmp), severity_filter="critical")
        for s in gen.to_dict()["suggestions"]:
            assert s["severity"] == "critical"
