"""Tests for the incident reconstruction module."""

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.reconstruct import (
    IncidentReconstructor,
    _assign_phase,
    _event_narrative_line,
    _sort_events,
    reconstruct_incident,
    format_reconstruct_text,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "event_id": "e1",
            "timestamp": "2026-01-15T10:00:00Z",
            "agent_id": "agent-alpha",
            "type": "initial_access",
            "action": "login",
            "target": "server-01",
            "outcome": "success",
        },
        {
            "event_id": "e2",
            "timestamp": "2026-01-15T10:05:00Z",
            "agent_id": "agent-alpha",
            "type": "execution",
            "action": "run_script",
            "target": "payload.sh",
            "outcome": "completed",
        },
        {
            "event_id": "e3",
            "timestamp": "2026-01-15T10:10:00Z",
            "agent_id": "agent-beta",
            "type": "lateral_movement",
            "action": "pivot",
            "target": "server-02",
            "outcome": "connected",
        },
        {
            "event_id": "e4",
            "timestamp": "2026-01-15T10:15:00Z",
            "agent_id": "agent-beta",
            "type": "data_exfiltration",
            "action": "upload",
            "target": "external-server",
            "outcome": "data transferred",
        },
        {
            "event_id": "e5",
            "timestamp": "2026-01-15T10:20:00Z",
            "agent_id": "agent-alpha",
            "type": "persistence",
            "action": "install_backdoor",
            "target": "server-01",
            "outcome": "backdoor installed",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def unordered_events() -> list[dict]:
    return [
        {"timestamp": "2026-01-15T10:10:00Z", "agent_id": "a1", "type": "exec"},
        {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "a2", "type": "login"},
        {"timestamp": "2026-01-15T10:05:00Z", "agent_id": "a3", "type": "scan"},
    ]


def test_sort_events_chronological(unordered_events):
    sorted_evs = _sort_events(unordered_events)
    timestamps = [e["timestamp"] for e in sorted_evs]
    assert timestamps == sorted(timestamps)


def test_assign_phase_initial_access():
    ev = {"type": "initial_access", "action": "login"}
    assert _assign_phase(ev) == "initial_access"


def test_assign_phase_execution():
    ev = {"type": "command", "action": "invoke"}
    assert _assign_phase(ev) == "execution"


def test_assign_phase_lateral_movement():
    ev = {"type": "lateral_movement", "action": "pivot"}
    assert _assign_phase(ev) == "lateral_movement"


def test_assign_phase_exfiltration():
    ev = {"type": "data_exfiltration"}
    assert _assign_phase(ev) == "data_exfiltration"


def test_assign_phase_persistence():
    ev = {"type": "persistence", "action": "implant"}
    assert _assign_phase(ev) == "persistence"


def test_assign_phase_from_techniques():
    ev = {"type": "unknown", "techniques": ["lateral_movement"]}
    assert _assign_phase(ev) == "lateral_movement"


def test_assign_phase_default():
    ev = {"type": "something_else", "action": "doStuff"}
    assert _assign_phase(ev) == "execution"


def test_narrative_line_full():
    ev = {
        "timestamp": "2026-01-15T10:00:00Z",
        "agent_id": "agent-1",
        "action": "ran exploit",
        "target": "db-server",
        "outcome": "root shell obtained",
    }
    line = _event_narrative_line(ev)
    assert "agent-1" in line
    assert "ran exploit" in line
    assert "db-server" in line
    assert "root shell obtained" in line


def test_narrative_line_minimal():
    ev = {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "a1"}
    line = _event_narrative_line(ev)
    assert "a1" in line


def test_reconstruct_full_pipeline(evidence_dir):
    r = IncidentReconstructor()
    events = r.load_events(evidence_dir)
    assert len(events) == 5

    timeline = r.build_timeline()
    assert len(timeline) == 5
    assert timeline[0]["event_id"] == "e1"
    assert timeline[-1]["event_id"] == "e5"

    phases = r.assign_phases()
    assert "initial_access" in phases
    assert "lateral_movement" in phases
    assert "data_exfiltration" in phases
    assert "persistence" in phases


def test_generate_narrative(evidence_dir):
    r = reconstruct_incident(evidence_dir)
    narrative = r.generate_narrative()
    assert "Incident Reconstruction" in narrative
    assert "Initial Access" in narrative
    assert "Lateral Movement" in narrative
    assert "agent-alpha" in narrative
    assert "agent-beta" in narrative
    assert "Total events: 5" in narrative


def test_to_dict(evidence_dir):
    r = reconstruct_incident(evidence_dir)
    data = r.to_dict()
    assert data["total_events"] == 5
    assert data["phases_observed"] >= 3
    assert "agent-alpha" in data["agents_involved"]
    assert "agent-beta" in data["agents_involved"]
    assert len(data["phases"]) >= 3
    assert len(data["timeline"]) == 5


def test_format_reconstruct_text(evidence_dir):
    r = reconstruct_incident(evidence_dir)
    text = format_reconstruct_text(r)
    assert "Phase:" in text
    assert "Summary" in text


def test_reconstruct_empty_dir(tmp_path):
    r = IncidentReconstructor()
    events = r.load_events(tmp_path)
    assert events == []
    r.build_timeline()
    r.assign_phases()
    narrative = r.generate_narrative()
    assert "No events" in narrative


def test_reconstruct_json_files(tmp_path):
    events = [
        {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "a1", "type": "execution"},
        {"timestamp": "2026-01-15T10:01:00Z", "agent_id": "a2", "type": "persistence"},
    ]
    (tmp_path / "data.json").write_text(json.dumps(events), encoding="utf-8")
    r = reconstruct_incident(tmp_path)
    assert r.to_dict()["total_events"] == 2


def test_phase_order_in_narrative(evidence_dir):
    r = reconstruct_incident(evidence_dir)
    narrative = r.generate_narrative()
    initial_pos = narrative.index("Initial Access")
    exfil_pos = narrative.index("Data Exfiltration")
    assert initial_pos < exfil_pos
