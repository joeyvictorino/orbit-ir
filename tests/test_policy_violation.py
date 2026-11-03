"""Tests for policy violation pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.policy_violation import (
    analyze_policy_violations,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_boundary_pushing(self):
        ev = {"message": "Agent pushed the boundary limits of file access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "boundary_pushing" in cats

    def test_policy_erosion(self):
        ev = {"message": "Detected policy erosion in enforcement rules over time"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "policy_erosion" in cats

    def test_selective_compliance(self):
        ev = {"message": "Agent shows selective compliance by following some easy rules"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "selective_compliance" in cats

    def test_circumvention(self):
        ev = {"message": "Agent used workaround to circumvent policy restrictions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "circumvention" in cats

    def test_rule_lawyering(self):
        ev = {"message": "Agent used rule lawyering to twist the wording of policy"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "rule_lawyering" in cats

    def test_policy_override(self):
        ev = {"message": "Agent attempted to override policy controls directly"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "policy_override" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent circumvented policy by pushing the boundary limits to override safeguard"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "CIRCUMVENT POLICY restriction via workaround"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "circumvention" in cats

    def test_repeated_minor_violations(self):
        ev = {"message": "Repeated minor violations eroding the policy enforcement over time"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "policy_erosion" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_policy_violations([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_policy_violations(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_policy_violations(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent pushed boundary limits", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "message": "Agent circumvented policy restrictions", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        r = analyze_policy_violations(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Gradual weakening of policy enforcement detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Override policy controls directly attempted", "timestamp": "t3"},
        ]
        r = analyze_policy_violations(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction"},
            {"agent_id": "a1", "message": "Agent bypassed policy controls again"},
        ]
        r = analyze_policy_violations(events)
        circ = [c for c in r.categories if c.category == "circumvention"]
        assert len(circ) == 1
        assert circ[0].count == 2

    def test_all_categories_present(self):
        r = analyze_policy_violations([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent circumvented policy restriction #{i}"} for i in range(50)]
        r = analyze_policy_violations(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_policy_violations([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Pushed the boundary limits once"},
        ]
        low_r = analyze_policy_violations(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent pushed the boundary limits again", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Another policy override attempt", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy controls", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent pushed boundary limits", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent pushed the boundary limits", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert len(chains[0].categories_seen) >= 1


class TestLoadEvents:
    def test_load_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([{"agent_id": "a1", "message": "test"}]))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_missing(self):
        events = _load_events("/nonexistent/path")
        assert events == []

    def test_load_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json")
            events = _load_events(td)
            assert events == []

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "single.json"
            p.write_text(json.dumps({"agent_id": "a1", "message": "test"}))
            events = _load_events(td)
            assert len(events) == 1


class TestFormat:
    def test_format_text_nonempty(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restrictions", "timestamp": "t1"},
        ]
        r = analyze_policy_violations(events)
        text = format_text(r)
        assert "Policy Violation" in text
        assert "circumvention" in text

    def test_format_text_empty(self):
        r = analyze_policy_violations([])
        text = format_text(r)
        assert "Policy Violation" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restrictions", "timestamp": "t1"},
        ]
        r = analyze_policy_violations(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_policy_violations([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent pushed the boundary limits", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Another policy override attempt detected", "timestamp": "t3"},
        ]
        r = analyze_policy_violations(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent circumvented policy restrictions", "timestamp": "t1"},
        ]
        r = analyze_policy_violations(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent circumvented policy restriction", "timestamp": "t1"},
            ]))
            r = analyze_policy_violations(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent pushed boundary limits", "timestamp": "t1"},
            ]))
            r = analyze_policy_violations(Path(td))
            assert r.violation_events == 1
