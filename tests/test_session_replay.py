"""Tests for the session replay module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.session_replay import (
    SessionReplayBuilder,
    replay_sessions,
    format_replay_text,
    format_replay_json,
    _is_anomaly,
    _group_sessions,
    _parse_ts,
    _annotate,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "timestamp": "2026-01-15T10:00:00Z",
            "agent_id": "agent-alpha",
            "actual_tool": "list_users",
            "tool_call_id": "tc1",
            "resource": "iam/users",
            "effect": "listed",
        },
        {
            "timestamp": "2026-01-15T10:01:00Z",
            "agent_id": "agent-alpha",
            "actual_tool": "read_config",
            "tool_call_id": "tc2",
            "resource": "config.yaml",
            "effect": "file-read",
        },
        {
            "timestamp": "2026-01-15T10:02:00Z",
            "agent_id": "agent-beta",
            "actual_tool": "create_role",
            "tool_call_id": "tc3",
            "resource": "roles/admin",
            "effect": "role-modified",
            "type": "anomaly",
            "severity": "high",
        },
        {
            "timestamp": "2026-01-15T10:03:00Z",
            "agent_id": "agent-alpha",
            "actual_tool": "write_file",
            "tool_call_id": "tc4",
            "resource": "/tmp/output.txt",
            "effect": "written",
        },
        {
            "timestamp": "2026-01-15T12:00:00Z",
            "agent_id": "agent-alpha",
            "actual_tool": "scan_ports",
            "tool_call_id": "tc5",
            "resource": "network/hosts",
            "effect": "scanned",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


def test_replay_basic(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    assert report.total_events == 5
    assert report.total_sessions >= 2
    assert "agent-alpha" in report.agents
    assert "agent-beta" in report.agents


def test_replay_agent_filter(evidence_dir: Path):
    report = replay_sessions(evidence_dir, agent_id="agent-beta")
    assert len(report.agents) == 1
    assert report.total_events == 1
    assert report.sessions[0].agent_id == "agent-beta"


def test_session_grouping_by_time_gap(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    alpha_sessions = [s for s in report.sessions if s.agent_id == "agent-alpha"]
    assert len(alpha_sessions) == 2
    assert alpha_sessions[0].event_count == 3
    assert alpha_sessions[1].event_count == 1


def test_anomaly_detection(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    beta_sessions = [s for s in report.sessions if s.agent_id == "agent-beta"]
    assert len(beta_sessions) == 1
    assert beta_sessions[0].anomaly_count == 1
    assert beta_sessions[0].entries[0].is_anomaly is True


def test_entry_fields(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    alpha_s1 = [s for s in report.sessions if s.agent_id == "agent-alpha"][0]
    first = alpha_s1.entries[0]
    assert first.action == "list_users"
    assert first.tool_call_id == "tc1"
    assert first.resource == "iam/users"
    assert first.effect == "listed"


def test_annotations_prev_next(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    alpha_s1 = [s for s in report.sessions if s.agent_id == "agent-alpha"][0]
    second = alpha_s1.entries[1]
    assert "after list_users" in second.annotation
    assert "before write_file" in second.annotation


def test_format_text(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    text = format_replay_text(report)
    assert "Session Replay Report" in text
    assert "agent-alpha" in text
    assert "agent-beta" in text
    assert "[!]" in text


def test_format_json(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    output = format_replay_json(report)
    parsed = json.loads(output)
    assert parsed["total_sessions"] >= 2
    assert parsed["total_events"] == 5
    assert len(parsed["sessions"]) >= 2


def test_is_anomaly():
    assert _is_anomaly({"type": "anomaly"}) is True
    assert _is_anomaly({"type": "normal"}) is False
    assert _is_anomaly({"severity": "critical"}) is True
    assert _is_anomaly({"severity": "low"}) is False
    assert _is_anomaly({"policy_decision": "denied"}) is True
    assert _is_anomaly({"policy_decision": "allowed"}) is False


def test_parse_ts():
    dt = _parse_ts("2026-01-15T10:00:00Z")
    assert dt is not None
    assert dt.hour == 10
    dt2 = _parse_ts("invalid")
    assert dt2 is None


def test_group_sessions():
    events = [
        {"agent_id": "a", "timestamp": "2026-01-15T10:00:00Z"},
        {"agent_id": "a", "timestamp": "2026-01-15T10:05:00Z"},
        {"agent_id": "a", "timestamp": "2026-01-15T12:00:00Z"},
    ]
    grouped = _group_sessions(events)
    assert len(grouped["a"]) == 2
    assert len(grouped["a"][0]) == 2
    assert len(grouped["a"][1]) == 1


def test_empty_evidence(tmp_path: Path):
    report = replay_sessions(tmp_path)
    assert report.total_sessions == 0
    assert report.total_events == 0


def test_builder_class(evidence_dir: Path):
    builder = SessionReplayBuilder()
    report = builder.replay(evidence_dir)
    assert report.total_events == 5


def test_session_start_end_times(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    alpha_s1 = [s for s in report.sessions if s.agent_id == "agent-alpha"][0]
    assert alpha_s1.start_time == "2026-01-15T10:00:00Z"
    assert alpha_s1.end_time == "2026-01-15T10:03:00Z"


def test_anomaly_annotation():
    ev = {"type": "anomaly", "severity": "high"}
    ann = _annotate(ev, None, None)
    assert "ANOMALY" in ann
    assert "high" in ann


def test_policy_denied_annotation():
    ev = {"type": "action", "policy_decision": "denied"}
    ann = _annotate(ev, None, None)
    assert "policy=denied" in ann


def test_single_event_session(tmp_path: Path):
    events = [
        {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "solo", "action": "ping"},
    ]
    (tmp_path / "ev.jsonl").write_text(json.dumps(events[0]), encoding="utf-8")
    report = replay_sessions(tmp_path)
    assert report.total_sessions == 1
    assert report.sessions[0].event_count == 1


def test_multiple_agents_separate_sessions(tmp_path: Path):
    events = [
        {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "a1", "action": "foo"},
        {"timestamp": "2026-01-15T10:00:00Z", "agent_id": "a2", "action": "bar"},
        {"timestamp": "2026-01-15T10:01:00Z", "agent_id": "a1", "action": "baz"},
    ]
    (tmp_path / "ev.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    report = replay_sessions(tmp_path)
    assert len(report.agents) == 2
    a1_sessions = [s for s in report.sessions if s.agent_id == "a1"]
    assert a1_sessions[0].event_count == 2


def test_json_roundtrip(evidence_dir: Path):
    report = replay_sessions(evidence_dir)
    output = format_replay_json(report)
    parsed = json.loads(output)
    assert "sessions" in parsed
    for sess in parsed["sessions"]:
        assert "entries" in sess
        for entry in sess["entries"]:
            assert "action" in entry
            assert "timestamp" in entry
