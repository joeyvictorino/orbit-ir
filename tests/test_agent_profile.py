"""Tests for orbit_ir.agent_profile."""

import json
from pathlib import Path

import pytest

from orbit_ir.agent_profile import (
    AgentProfiler,
    profile_evidence_agents,
    format_agent_profile_text,
    _assign_tags,
    _compute_risk_score,
)


@pytest.fixture
def evidence_dir(tmp_path):
    events = [
        {"timestamp": "2024-01-15T10:00:00Z", "agent_id": "agent-1", "action": "read", "target": "db-1", "severity": "low"},
        {"timestamp": "2024-01-15T10:01:00Z", "agent_id": "agent-1", "action": "read", "target": "db-2", "severity": "low"},
        {"timestamp": "2024-01-15T10:02:00Z", "agent_id": "agent-1", "action": "read", "target": "file-1", "severity": "info"},
        {"timestamp": "2024-01-15T10:03:00Z", "agent_id": "agent-1", "action": "write", "target": "file-2", "severity": "medium"},
        {"timestamp": "2024-01-15T10:00:00Z", "agent_id": "agent-2", "action": "execute", "target": "cmd-1", "severity": "high"},
        {"timestamp": "2024-01-15T10:05:00Z", "agent_id": "agent-2", "action": "sudo", "target": "system-1", "severity": "critical"},
        {"timestamp": "2024-01-15T10:10:00Z", "agent_id": "agent-2", "action": "delete", "target": "logs", "severity": "high"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events))
    return tmp_path


def test_profiler_loads_events(evidence_dir):
    profiler = AgentProfiler()
    events = profiler.load(evidence_dir)
    assert len(events) == 7


def test_profiler_builds_profiles(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiles = profiler.build_profiles()
    assert len(profiles) == 2
    names = [p["agent"] for p in profiles]
    assert "agent-1" in names
    assert "agent-2" in names


def test_profile_event_counts(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    p1 = next(p for p in profiler.profiles if p["agent"] == "agent-1")
    p2 = next(p for p in profiler.profiles if p["agent"] == "agent-2")
    assert p1["event_count"] == 4
    assert p2["event_count"] == 3


def test_profile_actions(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    p1 = next(p for p in profiler.profiles if p["agent"] == "agent-1")
    assert p1["actions"]["read"] == 3
    assert p1["actions"]["write"] == 1


def test_profile_severity_distribution(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    p2 = next(p for p in profiler.profiles if p["agent"] == "agent-2")
    assert p2["severity_distribution"]["high"] == 2
    assert p2["severity_distribution"]["critical"] == 1


def test_profile_duration(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    p1 = next(p for p in profiler.profiles if p["agent"] == "agent-1")
    assert p1["active_duration_seconds"] == 180  # 3 minutes


def test_data_collector_tag():
    profile = {
        "actions": {"read": 10, "write": 1},
        "targets": ["db-1", "db-2"],
        "severity_distribution": {"low": 10, "info": 1},
    }
    tags = _assign_tags(profile)
    assert "data_collector" in tags


def test_credential_harvester_tag():
    profile = {
        "actions": {"access": 5},
        "targets": ["credential-store", "password-vault", "api_key_db"],
        "severity_distribution": {"medium": 5},
    }
    tags = _assign_tags(profile)
    assert "credential_harvester" in tags


def test_high_privilege_tag():
    profile = {
        "actions": {"sudo": 2, "read": 3},
        "targets": ["system"],
        "severity_distribution": {"high": 2, "low": 3},
    }
    tags = _assign_tags(profile)
    assert "high_privilege" in tags


def test_stealthy_tag():
    profile = {
        "actions": {"execute": 2},
        "targets": ["target-1"],
        "severity_distribution": {"critical": 2},
    }
    tags = _assign_tags(profile)
    assert "stealthy" in tags


def test_risk_score_high_severity():
    profile = {
        "actions": {"execute": 1, "delete": 1},
        "targets": ["t1", "t2", "t3"],
        "severity_distribution": {"critical": 3},
    }
    score = _compute_risk_score(profile)
    assert score > 5.0


def test_risk_score_low_severity():
    profile = {
        "actions": {"read": 1},
        "targets": ["t1"],
        "severity_distribution": {"info": 5},
    }
    score = _compute_risk_score(profile)
    assert score < 2.0


def test_agent_filter(evidence_dir):
    profiler = profile_evidence_agents(evidence_dir, agent="agent-1")
    assert len(profiler.profiles) == 1
    assert profiler.profiles[0]["agent"] == "agent-1"


def test_min_risk_filter(evidence_dir):
    profiler = profile_evidence_agents(evidence_dir, min_risk=5.0)
    for p in profiler.profiles:
        assert p["risk_score"] >= 5.0


def test_to_dict(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    data = profiler.to_dict()
    assert data["total_agents"] == 2
    assert data["total_events"] == 7
    assert len(data["profiles"]) == 2


def test_format_text(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    text = format_agent_profile_text(profiler.to_dict())
    assert "Agent Profiles" in text
    assert "agent-1" in text
    assert "agent-2" in text


def test_format_text_empty():
    text = format_agent_profile_text({"profiles": [], "total_agents": 0, "total_events": 0})
    assert "No agent profiles found" in text


def test_empty_directory(tmp_path):
    profiler = AgentProfiler()
    profiler.load(tmp_path)
    profiles = profiler.build_profiles()
    assert len(profiles) == 0


def test_risk_indicators(evidence_dir):
    profiler = AgentProfiler()
    profiler.load(evidence_dir)
    profiler.build_profiles()
    p2 = next(p for p in profiler.profiles if p["agent"] == "agent-2")
    assert "has critical-severity events" in p2["risk_indicators"]
