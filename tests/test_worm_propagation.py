"""Tests for worm propagation pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.worm_propagation import (
    analyze_worm_propagation,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_lateral_spread(self):
        ev = {"message": "Agent performed lateral spread to adjacent systems"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "lateral_spread" in cats

    def test_self_replication(self):
        ev = {"message": "Malware self-replicated to new host machines"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "self_replication" in cats

    def test_autonomous_expansion(self):
        ev = {"message": "Autonomous spread beyond bounds without authorization"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "autonomous_expansion" in cats

    def test_payload_delivery(self):
        ev = {"message": "Delivered payload malware during propagation across hosts"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "payload_delivery" in cats

    def test_network_scanning(self):
        ev = {"message": "Scanning network subnet for new vulnerable targets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "network_scanning" in cats

    def test_persistence_seeding(self):
        ev = {"message": "Seeded persistence on new compromised hosts across network"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "persistence_seeding" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent lateral spread to adjacent host and scanning network for new targets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_empty_event(self):
        matches = _classify_event({})
        assert matches == []

    def test_case_insensitive(self):
        ev = {"message": "LATERAL SPREAD to ADJACENT SYSTEMS detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "lateral_spread" in cats

    def test_lateral_hop(self):
        ev = {"message": "Agent hopped to host in the adjacent network"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "lateral_spread" in cats

    def test_self_clone(self):
        ev = {"message": "Agent created clone of itself on remote host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "self_replication" in cats

    def test_uncontrolled_growth(self):
        ev = {"message": "Runaway expansion across multiple servers without control"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "autonomous_expansion" in cats

    def test_payload_with_propagation(self):
        ev = {"message": "Deployed payload malware during propagation of the worm"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "payload_delivery" in cats


class TestAnalyze:
    def test_empty_events(self):
        report = analyze_worm_propagation([])
        assert report.total_events == 0
        assert report.propagation_events == 0
        assert report.risk_score == 0.0
        assert report.risk_level == "none"

    def test_single_event(self):
        events = [{"message": "Agent lateral spread to adjacent systems", "agent_id": "agent-1"}]
        report = analyze_worm_propagation(events)
        assert report.total_events == 1
        assert report.propagation_events == 1
        assert report.risk_score > 0

    def test_no_propagation_events(self):
        events = [{"message": "Normal operation completed"}]
        report = analyze_worm_propagation(events)
        assert report.propagation_events == 0
        assert report.risk_level == "none"

    def test_multiple_events(self):
        events = [
            {"message": "Agent lateral spread to adjacent systems", "agent_id": "a1"},
            {"message": "Self-replicated to new host machines", "agent_id": "a1"},
            {"message": "Scanning network for vulnerable targets", "agent_id": "a2"},
        ]
        report = analyze_worm_propagation(events)
        assert report.total_events == 3
        assert report.propagation_events == 3
        assert len(report.agents_involved) == 2

    def test_risk_level_critical(self):
        events = [
            {"message": "Agent lateral spread to adjacent host", "agent_id": "a1"},
        ]
        report = analyze_worm_propagation(events)
        assert report.risk_score >= 0.5 or report.risk_level in ("critical", "high", "medium")

    def test_categories_populated(self):
        events = [{"message": "Agent lateral spread to adjacent systems"}]
        report = analyze_worm_propagation(events)
        assert len(report.categories) == len(CATEGORIES)

    def test_agents_tracked(self):
        events = [
            {"message": "Lateral spread to adjacent host", "agent_id": "agent-x"},
            {"message": "Self-replicated to new host", "agent_id": "agent-y"},
        ]
        report = analyze_worm_propagation(events)
        assert "agent-x" in report.agents_involved
        assert "agent-y" in report.agents_involved

    def test_risk_score_bounded(self):
        events = [{"message": "Lateral spread to adjacent systems"}] * 100
        report = analyze_worm_propagation(events)
        assert 0.0 <= report.risk_score <= 1.0


class TestChains:
    def test_no_chains_single_event(self):
        events = [{"message": "Agent lateral spread to adjacent host", "agent_id": "a1"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"message": "Agent lateral spread to adjacent host", "agent_id": "a1"},
            {"message": "Self-replicated to new host machines", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_multiple_agents_chains(self):
        events = [
            {"message": "Lateral spread to adjacent host", "agent_id": "a1"},
            {"message": "Self-replicated to new host", "agent_id": "a1"},
            {"message": "Scanning network for targets", "agent_id": "a2"},
            {"message": "Payload delivery during propagation across hosts", "agent_id": "a2"},
        ]
        chains = _detect_chains(events)
        agents = [c.agent for c in chains]
        assert "a1" in agents
        assert "a2" in agents

    def test_chain_score(self):
        events = [
            {"message": "Lateral spread to adjacent host", "agent_id": "a1"},
            {"message": "Self-replicated to new host", "agent_id": "a1"},
            {"message": "Scanning network for targets", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert chains[0].propagation_score > 0

    def test_chain_categories(self):
        events = [
            {"message": "Lateral spread to adjacent host", "agent_id": "a1"},
            {"message": "Self-replicated to new host", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert len(chains[0].categories_seen) >= 1

    def test_empty_events_no_chains(self):
        chains = _detect_chains([])
        assert chains == []


class TestLoadEvents:
    def test_load_from_directory(self):
        with tempfile.TemporaryDirectory() as td:
            data = [{"message": "test event", "agent_id": "a1"}]
            p = Path(td) / "events.json"
            p.write_text(json.dumps(data))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "event.json"
            p.write_text(json.dumps({"message": "single event"}))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_nonexistent(self):
        events = _load_events("/nonexistent/path/xyz")
        assert events == []

    def test_load_bad_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json{{{")
            events = _load_events(td)
            assert events == []

    def test_load_multiple_files(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(3):
                p = Path(td) / f"events_{i}.json"
                p.write_text(json.dumps([{"message": f"event {i}"}]))
            events = _load_events(td)
            assert len(events) == 3

    def test_load_non_json_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "readme.txt").write_text("not json")
            (Path(td) / "data.json").write_text(json.dumps([{"msg": "ok"}]))
            events = _load_events(td)
            assert len(events) == 1


class TestFormat:
    def test_format_text_empty(self):
        report = analyze_worm_propagation([])
        text = format_text(report)
        assert "Worm Propagation" in text
        assert "Total events: 0" in text

    def test_format_text_with_events(self):
        events = [
            {"message": "Agent lateral spread to adjacent systems", "agent_id": "a1"},
            {"message": "Self-replicated to new host machines", "agent_id": "a1"},
        ]
        report = analyze_worm_propagation(events)
        text = format_text(report)
        assert "lateral_spread" in text or "self_replication" in text
        assert "Propagation chains:" in text

    def test_format_text_risk(self):
        events = [{"message": "Lateral spread to adjacent host"}]
        report = analyze_worm_propagation(events)
        text = format_text(report)
        assert "Risk score:" in text

    def test_format_json_valid(self):
        events = [{"message": "Agent lateral spread to adjacent host", "agent_id": "a1"}]
        report = analyze_worm_propagation(events)
        output = format_json(report)
        data = json.loads(output)
        assert "total_events" in data
        assert "categories" in data

    def test_format_json_empty(self):
        report = analyze_worm_propagation([])
        output = format_json(report)
        data = json.loads(output)
        assert data["total_events"] == 0

    def test_format_json_no_raw(self):
        events = [
            {"message": "Agent lateral spread to adjacent host", "agent_id": "a1"},
            {"message": "Self-replicated to new host", "agent_id": "a1"},
        ]
        report = analyze_worm_propagation(events)
        output = format_json(report)
        assert '"raw"' not in output

    def test_format_text_agents(self):
        events = [
            {"message": "Lateral spread to adjacent host", "agent_id": "worm-1"},
        ]
        report = analyze_worm_propagation(events)
        text = format_text(report)
        assert "Agents involved:" in text
