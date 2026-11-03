"""Tests for watering hole attack pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.watering_hole import (
    analyze_watering_hole,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_resource_poisoning(self):
        ev = {"message": "Agent attempted to poison the shared resource cache"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "resource_poisoning" in cats

    def test_dependency_hijack(self):
        ev = {"message": "Detected dependency hijack of the package registry"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_hijack" in cats

    def test_endpoint_tampering(self):
        ev = {"message": "Agent attempted to tamper with the endpoint URL configuration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "endpoint_tampering" in cats

    def test_supply_chain_compromise(self):
        ev = {"message": "Detected supply chain compromise of the build pipeline"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "supply_chain_compromise" in cats

    def test_trust_exploitation(self):
        ev = {"message": "Agent attempted to exploit trust relationship with the service"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "trust_exploitation" in cats

    def test_update_mechanism_abuse(self):
        ev = {"message": "Agent attempted to hijack the update mechanism channel"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "update_mechanism_abuse" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent poisoned the shared resource and hijacked the dependency package to compromise supply chain"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DEPENDENCY HIJACK DETECTED in package registry"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_hijack" in cats

    def test_typosquatting(self):
        ev = {"message": "Detected typosquat attack on popular package name"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_hijack" in cats

    def test_dns_tampering(self):
        ev = {"message": "Agent attempted dns poison to redirect the service endpoint"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "endpoint_tampering" in cats

    def test_fake_update(self):
        ev = {"message": "Fake update server deployed to distribute malicious patches"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "update_mechanism_abuse" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_watering_hole([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_watering_hole(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
        ]
        r = analyze_watering_hole(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Detected dependency hijack of the package registry", "timestamp": "t2"},
        ]
        r = analyze_watering_hole(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Detected supply chain compromise of the build pipeline", "timestamp": "t3"},
        ]
        r = analyze_watering_hole(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned the shared resource cache"},
            {"agent_id": "a1", "message": "Another resource cache was poisoned by the agent"},
        ]
        r = analyze_watering_hole(events)
        rp = [c for c in r.categories if c.category == "resource_poisoning"]
        assert len(rp) == 1
        assert rp[0].count == 2

    def test_all_categories_present(self):
        r = analyze_watering_hole([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent poisoned the shared resource cache #{i}"} for i in range(50)]
        r = analyze_watering_hole(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_watering_hole([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent tampered with the endpoint URL once"},
        ]
        low_r = analyze_watering_hole(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Detected supply chain compromise of the build pipeline", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
        ]
        r = analyze_watering_hole(events)
        text = format_text(r)
        assert "Watering Hole" in text
        assert "resource_poisoning" in text

    def test_format_text_empty(self):
        r = analyze_watering_hole([])
        text = format_text(r)
        assert "Watering Hole" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
        ]
        r = analyze_watering_hole(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_watering_hole([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Detected supply chain compromise of the build pipeline", "timestamp": "t3"},
        ]
        r = analyze_watering_hole(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
        ]
        r = analyze_watering_hole(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent attempted to poison the shared resource cache", "timestamp": "t1"},
            ]))
            r = analyze_watering_hole(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Detected dependency hijack of the package", "timestamp": "t1"},
            ]))
            r = analyze_watering_hole(Path(td))
            assert r.violation_events == 1
