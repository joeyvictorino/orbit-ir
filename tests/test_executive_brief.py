"""Tests for executive briefing generator."""
import json
from pathlib import Path

import pytest

from orbit_ir.executive_brief import (
    ExecutiveBriefGenerator,
    format_brief_markdown,
    format_brief_text,
    generate_executive_brief,
)


def _write_events(events: list[dict], tmp_path: Path) -> Path:
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return f


def test_empty_brief():
    gen = ExecutiveBriefGenerator([])
    data = gen.generate()
    assert data["title"] == "Incident Executive Briefing"
    assert data["key_metrics"]["total_events"] == 0
    assert data["narrative"] == "No events were observed during the analysis period."
    assert data["status"] == "contained"


def test_single_event():
    events = [{"agent_id": "a1", "action": "read_file", "timestamp": "2024-01-01T00:00:00Z"}]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert data["key_metrics"]["total_events"] == 1
    assert data["key_metrics"]["unique_agents"] == 1


def test_severity_escalation():
    events = [
        {"agent_id": "a1", "severity": "low"},
        {"agent_id": "a1", "severity": "critical"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert data["key_metrics"]["overall_severity"] == "critical"
    assert data["status"] == "active"


def test_timeline_calculation():
    events = [
        {"agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z"},
        {"agent_id": "a1", "timestamp": "2024-01-01T02:00:00Z"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert data["key_metrics"]["timeline_hours"] == 2.0


def test_multiple_agents_counted():
    events = [
        {"agent_id": "a1", "action": "read"},
        {"agent_id": "a2", "action": "write"},
        {"agent_id": "a3", "action": "exec"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert data["key_metrics"]["unique_agents"] == 3


def test_techniques_counted():
    events = [
        {"agent_id": "a1", "technique": "credential_reuse"},
        {"agent_id": "a1", "technique": "lateral_movement"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert data["key_metrics"]["techniques_observed"] == 2


def test_affected_systems():
    events = [
        {"agent_id": "a1", "target": "db-server-1"},
        {"agent_id": "a1", "target": "web-server-2"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert "db-server-1" in data["affected_systems"]
    assert "web-server-2" in data["affected_systems"]


def test_top_risks_from_detection_types():
    events = [
        {"agent_id": "a1", "detection_type": "credential_reuse"},
        {"agent_id": "a1", "detection_type": "credential_reuse"},
        {"agent_id": "a1", "detection_type": "lateral_movement"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert len(data["top_risks"]) > 0
    risk_names = [r["risk"] for r in data["top_risks"]]
    assert "Credential Reuse" in risk_names


def test_recommendations_from_known_techniques():
    events = [
        {"agent_id": "a1", "detection_type": "privilege_escalation"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    actions = data["recommended_actions"]
    assert len(actions) >= 1
    assert actions[0]["priority"] == 1
    assert "privilege" in actions[0]["action"].lower() or "permissions" in actions[0]["action"].lower()


def test_default_recommendation_when_unknown():
    events = [{"agent_id": "a1", "action": "something_unknown"}]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert len(data["recommended_actions"]) >= 1


def test_classification_custom():
    gen = ExecutiveBriefGenerator([], classification="TOP SECRET")
    data = gen.generate()
    assert data["classification"] == "TOP SECRET"


def test_narrative_with_time_range():
    events = [
        {"agent_id": "a1", "action": "scan", "timestamp": "2024-01-01T00:00:00Z"},
        {"agent_id": "a1", "action": "exfil", "timestamp": "2024-01-01T06:00:00Z"},
    ]
    gen = ExecutiveBriefGenerator(events)
    data = gen.generate()
    assert "2024-01-01" in data["narrative"]


def test_load_from_file(tmp_path):
    events = [{"agent_id": "a1", "action": "scan", "severity": "high"}]
    f = _write_events(events, tmp_path)
    gen = ExecutiveBriefGenerator()
    gen.load_events(f)
    data = gen.generate()
    assert data["key_metrics"]["total_events"] == 1


def test_load_from_directory(tmp_path):
    events = [{"agent_id": "a1"}, {"agent_id": "a2"}]
    (tmp_path / "ev.jsonl").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    gen = ExecutiveBriefGenerator()
    gen.load_events(tmp_path)
    data = gen.generate()
    assert data["key_metrics"]["unique_agents"] == 2


def test_format_brief_text():
    gen = ExecutiveBriefGenerator([{"agent_id": "a1", "severity": "high"}])
    data = gen.generate()
    text = format_brief_text(data)
    assert "KEY METRICS" in text
    assert "NARRATIVE" in text


def test_format_brief_markdown():
    gen = ExecutiveBriefGenerator([{"agent_id": "a1", "severity": "high"}])
    data = gen.generate()
    md = format_brief_markdown(data)
    assert "## Key Metrics" in md
    assert "## Narrative" in md


def test_generate_executive_brief_helper(tmp_path):
    events = [{"agent_id": "a1", "technique": "recon"}]
    f = _write_events(events, tmp_path)
    gen = generate_executive_brief(f, classification="RESTRICTED")
    data = gen.to_dict()
    assert data["classification"] == "RESTRICTED"


def test_to_dict_alias():
    gen = ExecutiveBriefGenerator([{"agent_id": "a1"}])
    assert gen.to_dict() == gen.generate()
