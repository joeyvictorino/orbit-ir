"""Tests for the counterfactual analysis module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.counterfactual import (
    CounterfactualAnalyzer,
    CounterfactualResult,
    ScenarioDefinition,
    DEFAULT_SCENARIOS,
    analyze_counterfactual,
    format_counterfactual_text,
    _load_scenarios,
    _event_matches_keywords,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "id": "ev-001",
            "timestamp": "2026-01-15T10:00:00Z",
            "agent_id": "agent-alpha",
            "type": "initial_access",
            "description": "Agent gained initial foothold",
        },
        {
            "id": "ev-002",
            "timestamp": "2026-01-15T10:01:00Z",
            "agent_id": "agent-alpha",
            "type": "credential_reuse",
            "credential": "stolen-token-abc",
            "description": "Reused stolen credential to authenticate",
        },
        {
            "id": "ev-003",
            "timestamp": "2026-01-15T10:02:00Z",
            "src_agent": "agent-alpha",
            "dst_agent": "agent-beta",
            "type": "lateral_movement",
            "description": "Pivoted from alpha to beta via SSH",
        },
        {
            "id": "ev-004",
            "timestamp": "2026-01-15T10:03:00Z",
            "agent_id": "agent-beta",
            "type": "privilege_escalation",
            "description": "Escalated to admin privileges",
        },
        {
            "id": "ev-005",
            "timestamp": "2026-01-15T10:04:00Z",
            "agent_id": "agent-beta",
            "type": "data_exfiltration",
            "description": "Exfiltrated sensitive data",
        },
    ]
    edir = tmp_path / "evidence"
    edir.mkdir()
    (edir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return edir


@pytest.fixture
def detections() -> list[dict]:
    return [
        {"detection_id": "det-001", "type": "credential_theft", "severity": "high"},
        {"detection_id": "det-002", "type": "lateral_movement", "severity": "critical"},
        {"detection_id": "det-003", "type": "data_exfiltration", "severity": "critical"},
    ]


class TestScenarioDefinition:
    def test_matches_by_keyword(self):
        s = ScenarioDefinition(
            name="test",
            description="test scenario",
            keywords=["credential", "token"],
        )
        assert s.matches_event({"credential": "abc", "type": "auth"})
        assert not s.matches_event({"type": "log", "message": "hello"})

    def test_matches_by_event_type(self):
        s = ScenarioDefinition(
            name="test",
            description="test scenario",
            event_types=["lateral_movement"],
        )
        assert s.matches_event({"type": "lateral_movement"})
        assert not s.matches_event({"type": "log_entry"})

    def test_matches_combined(self):
        s = ScenarioDefinition(
            name="test",
            description="test scenario",
            keywords=["ssh"],
            event_types=["privilege_escalation"],
        )
        assert s.matches_event({"type": "privilege_escalation"})
        assert s.matches_event({"description": "connected via SSH"})


class TestEventMatchesKeywords:
    def test_matches(self):
        assert _event_matches_keywords(
            {"credential": "tok123"}, frozenset(["credential"])
        )

    def test_no_match(self):
        assert not _event_matches_keywords(
            {"type": "info"}, frozenset(["credential"])
        )


class TestDefaultScenarios:
    def test_three_defaults(self):
        assert len(DEFAULT_SCENARIOS) == 3
        names = {s.name for s in DEFAULT_SCENARIOS}
        assert "credential_rotation" in names
        assert "network_segmentation" in names
        assert "access_control" in names


class TestLoadScenarios:
    def test_none_returns_defaults(self):
        scenarios = _load_scenarios(None)
        assert len(scenarios) == len(DEFAULT_SCENARIOS)

    def test_nonexistent_file_returns_defaults(self, tmp_path):
        scenarios = _load_scenarios(tmp_path / "nope.yaml")
        assert len(scenarios) == len(DEFAULT_SCENARIOS)

    def test_load_json_scenarios(self, tmp_path):
        data = {
            "scenarios": [
                {
                    "name": "custom",
                    "description": "Custom scenario",
                    "keywords": ["phishing"],
                    "event_types": ["email_send"],
                },
            ]
        }
        p = tmp_path / "scenarios.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        scenarios = _load_scenarios(p)
        assert len(scenarios) == 1
        assert scenarios[0].name == "custom"
        assert "phishing" in scenarios[0].keywords

    def test_load_invalid_json_returns_defaults(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        scenarios = _load_scenarios(p)
        assert len(scenarios) == len(DEFAULT_SCENARIOS)

    def test_load_empty_scenarios_returns_defaults(self, tmp_path):
        data = {"scenarios": []}
        p = tmp_path / "empty.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        scenarios = _load_scenarios(p)
        assert len(scenarios) == len(DEFAULT_SCENARIOS)


class TestCounterfactualAnalyzer:
    def test_analyze_default_scenarios(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        assert len(results) == 3
        for r in results:
            assert "scenario" in r
            assert "prevented_events" in r
            assert "reduction_pct" in r
            assert "timeline_impact" in r
            assert r["total_events"] > 0

    def test_credential_rotation_prevents_events(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        cred = next(r for r in results if r["scenario"] == "credential_rotation")
        assert cred["prevented_events"] > 0

    def test_network_segmentation_prevents_lateral(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        net = next(r for r in results if r["scenario"] == "network_segmentation")
        assert net["prevented_events"] > 0

    def test_access_control_prevents_escalation(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        ac = next(r for r in results if r["scenario"] == "access_control")
        assert ac["prevented_events"] > 0

    def test_custom_scenarios(self, evidence_dir, detections):
        custom = [
            ScenarioDefinition(
                name="custom_block",
                description="Block all API calls",
                keywords=["api", "endpoint"],
                event_types=["api_call"],
            ),
        ]
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir, scenarios=custom)
        assert len(results) == 1
        assert results[0]["scenario"] == "custom_block"

    def test_empty_results(self, evidence_dir):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze([], evidence_dir)
        assert len(results) == 3
        for r in results:
            assert r["total_events"] > 0

    def test_empty_evidence(self, tmp_path, detections):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, empty_dir)
        assert len(results) == 3
        for r in results:
            assert r["total_events"] == len(detections)

    def test_nonexistent_evidence(self, tmp_path, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, tmp_path / "nope")
        assert len(results) == 3

    def test_reduction_pct_range(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        for r in results:
            assert 0.0 <= r["reduction_pct"] <= 100.0

    def test_timeline_impact_labels(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        valid_impacts = {"none", "minor", "moderate", "major"}
        for r in results:
            assert r["timeline_impact"] in valid_impacts

    def test_prevented_agents_populated(self, evidence_dir, detections):
        analyzer = CounterfactualAnalyzer()
        results = analyzer.analyze(detections, evidence_dir)
        all_agents = set()
        for r in results:
            all_agents.update(r["prevented_agents"])
        assert len(all_agents) > 0


class TestAnalyzeCounterfactual:
    def test_convenience_function(self, evidence_dir, detections):
        results = analyze_counterfactual(detections, evidence_dir)
        assert len(results) == 3

    def test_with_scenario_file(self, tmp_path, evidence_dir, detections):
        data = {
            "scenarios": [
                {
                    "name": "file_scenario",
                    "description": "From file",
                    "keywords": ["exfiltrat"],
                },
            ]
        }
        sf = tmp_path / "scenarios.json"
        sf.write_text(json.dumps(data), encoding="utf-8")
        results = analyze_counterfactual(detections, evidence_dir, scenario_file=sf)
        assert len(results) == 1
        assert results[0]["scenario"] == "file_scenario"


class TestFormatCounterfactualText:
    def test_format_output(self, evidence_dir, detections):
        results = analyze_counterfactual(detections, evidence_dir)
        text = format_counterfactual_text(results)
        assert "Counterfactual Analysis" in text
        assert "credential_rotation" in text
        assert "reduction" in text.lower()

    def test_format_empty(self):
        text = format_counterfactual_text([])
        assert "No scenarios" in text

    def test_most_effective_shown(self, evidence_dir, detections):
        results = analyze_counterfactual(detections, evidence_dir)
        text = format_counterfactual_text(results)
        assert "Most effective" in text or "No scenario" in text


class TestCounterfactualResult:
    def test_to_dict(self):
        r = CounterfactualResult(
            scenario="test",
            description="Test scenario",
            total_events=10,
            prevented_events=3,
            remaining_events=7,
            reduction_pct=30.0,
        )
        d = r.to_dict()
        assert d["scenario"] == "test"
        assert d["reduction_pct"] == 30.0
        assert isinstance(d["prevented_event_ids"], list)
