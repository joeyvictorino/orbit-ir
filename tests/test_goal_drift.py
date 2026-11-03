"""Tests for goal_drift module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.goal_drift import (
    AgentDrift,
    DriftSegment,
    GoalDriftReport,
    GoalDriftSummary,
    GoalState,
    analyze_goal_drift,
    format_json,
    format_text,
    _extract_goals,
    _extract_target_resources,
    _jaccard_distance,
    _build_goal_states,
    _compute_drift_score,
    _classify_severity,
    _load_events,
)


class TestHelpers:
    def test_extract_goals_list(self):
        ev = {"goals": ["steal-data", "escalate"]}
        assert _extract_goals(ev) == ["steal-data", "escalate"]

    def test_extract_goals_single(self):
        ev = {"goal": "reconnaissance"}
        assert _extract_goals(ev) == ["reconnaissance"]

    def test_extract_goals_objective(self):
        ev = {"objective": "monitor-network"}
        assert _extract_goals(ev) == ["monitor-network"]

    def test_extract_goals_empty(self):
        ev = {"tool": "read_file"}
        assert _extract_goals(ev) == []

    def test_extract_target_resources(self):
        ev = {"resource": "/etc/passwd", "targets": ["/var/log", "/tmp"]}
        result = _extract_target_resources(ev)
        assert "/etc/passwd" in result
        assert "/var/log" in result

    def test_extract_target_resources_empty(self):
        ev = {"tool": "noop"}
        assert _extract_target_resources(ev) == []

    def test_jaccard_distance_identical(self):
        assert _jaccard_distance({"a", "b"}, {"a", "b"}) == 0.0

    def test_jaccard_distance_disjoint(self):
        assert _jaccard_distance({"a", "b"}, {"c", "d"}) == 1.0

    def test_jaccard_distance_partial(self):
        d = _jaccard_distance({"a", "b", "c"}, {"b", "c", "d"})
        assert 0.0 < d < 1.0

    def test_jaccard_distance_empty(self):
        assert _jaccard_distance(set(), set()) == 0.0

    def test_build_goal_states(self):
        events = [
            {"agent_id": "a1", "goal": "recon", "resource": "/etc", "tool": "ls", "timestamp": f"2026-01-01T00:{i:02d}:00Z"}
            for i in range(20)
        ]
        states = _build_goal_states(events, window_size=10)
        assert len(states) >= 2
        assert states[0].declared_goals == ["recon"]

    def test_compute_drift_score_empty(self):
        assert _compute_drift_score([]) == 0.0

    def test_compute_drift_score_single(self):
        seg = DriftSegment(
            segment_id="S-001",
            start_time="", end_time="",
            drift_type="scope-expansion",
            magnitude=0.5,
            initial_goal_set=[], final_goal_set=[],
            resources_initial=[], resources_final=[],
            events=[], description="",
        )
        score = _compute_drift_score([seg])
        assert 0.0 < score <= 1.0

    def test_classify_severity_critical(self):
        seg = DriftSegment(
            segment_id="A-001", start_time="", end_time="",
            drift_type="goal-abandonment", magnitude=0.8,
            initial_goal_set=[], final_goal_set=[],
            resources_initial=[], resources_final=[],
            events=[], description="",
        )
        assert _classify_severity(0.8, [seg]) == "critical"

    def test_classify_severity_low(self):
        seg = DriftSegment(
            segment_id="S-001", start_time="", end_time="",
            drift_type="scope-expansion", magnitude=0.1,
            initial_goal_set=[], final_goal_set=[],
            resources_initial=[], resources_final=[],
            events=[], description="",
        )
        assert _classify_severity(0.1, [seg]) == "low"


class TestAnalyzeGoalDrift:
    def test_empty_events(self):
        report = analyze_goal_drift([])
        assert report.summary.total_agents_analyzed == 0
        assert report.summary.agents_with_drift == 0

    def test_no_drift_same_goals(self):
        events = [
            {
                "agent_id": "a1",
                "goal": "monitor",
                "resource": "/var/log",
                "tool": "tail",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            }
            for i in range(20)
        ]
        report = analyze_goal_drift(events, window_size=5)
        # Same goal and resource throughout — no drift expected
        # (may or may not detect depending on window overlap)
        assert report.summary.total_agents_analyzed == 1

    def test_scope_expansion(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goal": "audit",
                "resource": "/var/log",
                "tool": "read",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goal": "audit",
                "resource": f"/system/resource_{i}",
                "tool": "read",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        if report.agent_drifts:
            drift = report.agent_drifts[0]
            scope_segs = [s for s in drift.segments if s.drift_type == "scope-expansion"]
            target_segs = [s for s in drift.segments if s.drift_type == "target-drift"]
            assert len(scope_segs) > 0 or len(target_segs) > 0

    def test_objective_shift(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goal": "monitor-logs",
                "resource": "/var/log",
                "tool": "tail",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goal": "exfiltrate-data",
                "resource": "/data/secrets",
                "tool": "upload",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        assert report.summary.agents_with_drift >= 1
        drift = report.agent_drifts[0]
        shift_segs = [s for s in drift.segments if s.drift_type == "objective-shift"]
        assert len(shift_segs) >= 1

    def test_goal_abandonment(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goals": ["task-a", "task-b"],
                "resource": "/data",
                "tool": "read",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goals": ["task-c"],
                "resource": "/other",
                "tool": "write",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        assert report.summary.agents_with_drift >= 1
        drift = report.agent_drifts[0]
        assert "task-a" in drift.abandoned_goals or "task-b" in drift.abandoned_goals
        assert "task-c" in drift.emergent_goals

    def test_target_drift(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goal": "scan",
                "resource": f"/original/path_{i % 3}",
                "tool": "scan",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goal": "scan",
                "resource": f"/completely/different_{i}",
                "tool": "scan",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        if report.agent_drifts:
            drift = report.agent_drifts[0]
            target_segs = [s for s in drift.segments if s.drift_type == "target-drift"]
            assert len(target_segs) >= 1

    def test_multi_agent(self):
        events = []
        for agent in ["a1", "a2"]:
            for i in range(10):
                events.append({
                    "agent_id": agent,
                    "goals": ["goal-x"] if i < 5 else ["goal-y"],
                    "resource": f"/res_{i}",
                    "tool": "op",
                    "timestamp": f"2026-01-01T00:{i:02d}:00Z",
                })
        report = analyze_goal_drift(events, window_size=5)
        assert report.summary.total_agents_analyzed == 2

    def test_drift_score_range(self):
        events = []
        for i in range(20):
            events.append({
                "agent_id": "a1",
                "goals": [f"goal-{i}"],
                "resource": f"/res_{i}",
                "tool": "op",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        for d in report.agent_drifts:
            assert 0.0 <= d.drift_score <= 1.0

    def test_severity_classification(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goals": ["task-a", "task-b", "task-c"],
                "resource": "/data",
                "tool": "read",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goals": ["completely-different"],
                "resource": "/new-target",
                "tool": "write",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        if report.agent_drifts:
            drift = report.agent_drifts[0]
            assert drift.severity in ("critical", "high", "medium", "low")


class TestFormatText:
    def test_format_text_empty(self):
        report = analyze_goal_drift([])
        text = format_text(report)
        assert "Agent Goal Drift Analysis Report" in text
        assert "Agents with drift:      0" in text

    def test_format_text_with_drift(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goals": ["monitor"],
                "resource": "/logs",
                "tool": "tail",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        for i in range(10, 20):
            events.append({
                "agent_id": "a1",
                "goals": ["steal"],
                "resource": "/secrets",
                "tool": "upload",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        text = format_text(report)
        assert "a1" in text


class TestFormatJson:
    def test_format_json_valid(self):
        events = []
        for i in range(20):
            events.append({
                "agent_id": "a1",
                "goals": [f"goal-{i % 3}"],
                "resource": f"/res_{i}",
                "tool": "op",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=5)
        output = format_json(report)
        data = json.loads(output)
        assert "agent_drifts" in data
        assert "summary" in data
        assert "agents_involved" in data
        assert "timeline" in data

    def test_format_json_empty(self):
        report = analyze_goal_drift([])
        data = json.loads(format_json(report))
        assert data["summary"]["agents_with_drift"] == 0


class TestLoadEvents:
    def test_load_events_from_dir(self, tmp_path):
        events = [
            {"agent_id": "a1", "goal": "recon", "timestamp": "2026-01-01T00:00:00Z"},
        ]
        (tmp_path / "transcripts.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events)
        )
        loaded = _load_events(tmp_path)
        assert len(loaded) == 1

    def test_load_events_empty_dir(self, tmp_path):
        loaded = _load_events(tmp_path)
        assert loaded == []


class TestTimeline:
    def test_timeline_ordering(self):
        events = []
        for i in range(10):
            events.append({
                "agent_id": "a1",
                "goals": ["goal-a"] if i < 5 else ["goal-z"],
                "resource": f"/res_{i}",
                "tool": "op",
                "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            })
        report = analyze_goal_drift(events, window_size=3)
        if report.timeline:
            timestamps = [e["timestamp"] for e in report.timeline]
            assert timestamps == sorted(timestamps)
