"""Tests for agent coordination analysis."""

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.coordination import analyze, format_text, format_json, CoordinationReport


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    d = tmp_path / "evidence"
    d.mkdir()
    f = d / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return d


def test_empty_evidence(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "empty.jsonl").write_text("", encoding="utf-8")
    r = analyze(d)
    assert r.metrics.total_agents == 0
    assert r.metrics.total_events == 0


def test_single_agent(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "agent-1", "action": "scan"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "agent-1", "action": "report"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.metrics.total_agents == 1
    assert r.metrics.handoff_count == 0
    assert r.metrics.coordination_score == 0.0


def test_multi_agent_handoffs(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "agent-1", "action": "detect"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "agent-2", "action": "investigate"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "agent-1", "action": "contain"},
        {"timestamp": "2024-01-01T00:03:00Z", "agent_id": "agent-3", "action": "remediate"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.metrics.total_agents == 3
    assert r.metrics.handoff_count == 3
    assert len(r.handoffs) == 3
    assert r.handoffs[0].from_agent == "agent-1"
    assert r.handoffs[0].to_agent == "agent-2"


def test_info_sharing_events(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "agent-1", "action": "detect"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "agent-1", "action": "share"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "agent-2", "action": "notify"},
        {"timestamp": "2024-01-01T00:03:00Z", "agent_id": "agent-2", "action": "escalate"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.metrics.info_sharing_events == 3


def test_sync_events(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "agent-1", "action": "sync"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "agent-2", "action": "acknowledge"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "agent-1", "action": "confirm"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.metrics.synchronization_points == 3


def test_shared_targets(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "agent-1", "action": "scan", "target": "server-1"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "agent-2", "action": "scan", "target": "server-1"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "agent-2", "action": "scan", "target": "server-2"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    shared = [p for p in r.agent_pairs if p.interaction_count > 0]
    assert len(shared) >= 1
    assert "server-1" in shared[0].shared_targets


def test_coordination_score_bounded(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "share"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "a2", "action": "notify"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "a3", "action": "sync"},
        {"timestamp": "2024-01-01T00:03:00Z", "agent_id": "a4", "action": "escalate"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert 0.0 <= r.metrics.coordination_score <= 1.0


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "detect"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "a2", "action": "respond"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    text = format_text(r)
    assert "Agent Coordination Analysis" in text
    assert "Handoff count" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "a1", "action": "detect"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    j = format_json(r)
    data = json.loads(j)
    assert "metrics" in data
    assert "agents" in data


def test_agents_sorted(tmp_path):
    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "agent_id": "charlie", "action": "a"},
        {"timestamp": "2024-01-01T00:01:00Z", "agent_id": "alice", "action": "b"},
        {"timestamp": "2024-01-01T00:02:00Z", "agent_id": "bob", "action": "c"},
    ]
    d = _write_events(tmp_path, events)
    r = analyze(d)
    assert r.agents == ["alice", "bob", "charlie"]
