from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.playbook import (
    PlaybookGenerator,
    generate_playbook,
    format_playbook_text,
    format_playbook_markdown,
    PLAYBOOK_KB,
    _classify_event,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "timestamp": "2024-01-15T10:00:00Z",
            "agent_id": "agent-1",
            "detection_type": "credential_compromise",
            "severity": "critical",
            "description": "shared credentials detected",
            "credential": "api_key_12345",
        },
        {
            "timestamp": "2024-01-15T10:05:00Z",
            "agent_id": "agent-2",
            "detection_type": "data_exfiltration",
            "severity": "critical",
            "description": "unauthorized bulk data transfer",
            "resource": "customer_db",
        },
        {
            "timestamp": "2024-01-15T10:10:00Z",
            "agent_id": "agent-1",
            "detection_type": "lateral_movement",
            "severity": "high",
            "target_agent": "agent-3",
            "tool_name": "ssh_tool",
        },
    ]
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events))
    return tmp_path


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    p = tmp_path / "empty.json"
    p.write_text("[]")
    return tmp_path


def test_playbook_kb_has_enough_types() -> None:
    assert len(PLAYBOOK_KB) >= 8


def test_playbook_kb_entries_have_required_fields() -> None:
    for key, entry in PLAYBOOK_KB.items():
        assert "title" in entry, f"{key} missing title"
        assert "severity" in entry, f"{key} missing severity"
        assert "containment" in entry, f"{key} missing containment"
        assert "investigation" in entry, f"{key} missing investigation"
        assert "remediation" in entry, f"{key} missing remediation"
        assert "notification" in entry, f"{key} missing notification"
        assert len(entry["containment"]) >= 2, f"{key} too few containment steps"


def test_classify_event_by_detection_type() -> None:
    event = {"detection_type": "credential_compromise", "severity": "high"}
    types = _classify_event(event)
    assert "credential_compromise" in types


def test_classify_event_by_keywords() -> None:
    event = {"description": "agent attempted privilege escalation via admin tool"}
    types = _classify_event(event)
    assert "privilege_escalation" in types


def test_classify_event_empty() -> None:
    types = _classify_event({})
    assert isinstance(types, list)


def test_generate_playbook_basic(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    assert "incident_summary" in data
    assert "affected_assets" in data
    assert "immediate_actions" in data
    assert "investigation_steps" in data
    assert "remediation" in data
    assert "communication" in data
    assert "post_incident" in data


def test_playbook_severity_detection(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    assert data["incident_summary"]["overall_severity"] in ("critical", "high")


def test_playbook_detects_agents(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    agents = data["affected_assets"]["agents"]
    assert "agent-1" in agents
    assert "agent-2" in agents


def test_playbook_detects_resources(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    resources = data["affected_assets"]["resources"]
    assert any("customer_db" in r for r in resources)


def test_playbook_containment_steps(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    actions = data["immediate_actions"]
    assert len(actions) > 0
    for action in actions:
        assert "steps" in action
        assert "severity" in action
        assert len(action["steps"]) > 0


def test_playbook_communication_urgency(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    comm = data["communication"]
    assert "urgency" in comm
    assert comm["urgency"] in ("immediate", "urgent", "normal", "informational")


def test_playbook_severity_threshold(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict(severity_threshold="critical")
    for action in data["immediate_actions"]:
        assert action["severity"] == "critical"


def test_playbook_empty_evidence(empty_dir: Path) -> None:
    gen = generate_playbook(empty_dir)
    data = gen.to_dict()
    assert data["incident_summary"]["event_count"] == 0
    assert len(data["immediate_actions"]) == 0


def test_playbook_references(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    refs = data.get("references", [])
    assert isinstance(refs, list)


def test_playbook_post_incident_lessons(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    post = data["post_incident"]
    assert "lessons_learned" in post
    assert len(post["lessons_learned"]) > 0


def test_format_playbook_text_structure(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    text = format_playbook_text(gen.to_dict())
    assert "INCIDENT RESPONSE PLAYBOOK" in text
    assert "INCIDENT SUMMARY" in text
    assert "AFFECTED ASSETS" in text
    assert "IMMEDIATE ACTIONS" in text
    assert "INVESTIGATION" in text


def test_format_playbook_markdown(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    md = format_playbook_markdown(gen.to_dict())
    assert "# Incident Response Playbook" in md
    assert "## 1. Incident Summary" in md
    assert "- [ ]" in md


def test_playbook_timestamps(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    summary = data["incident_summary"]
    assert summary["first_event"] is not None
    assert summary["last_event"] is not None


def test_playbook_credentials_detected(evidence_dir: Path) -> None:
    gen = generate_playbook(evidence_dir)
    data = gen.to_dict()
    creds = data["affected_assets"]["credentials"]
    assert len(creds) > 0
