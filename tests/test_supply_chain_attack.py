"""Tests for supply chain attack detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.supply_chain_attack import (
    analyze_supply_chain_attacks,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_dependency_poisoning(self):
        ev = {"message": "Agent injected malicious code into dependency package tree"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_poisoning" in cats

    def test_build_tampering(self):
        ev = {"message": "Agent tampered build process to inject backdoor code"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "build_tampering" in cats

    def test_package_substitution(self):
        ev = {"message": "Agent performed typosquat package attack on npm registry"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "package_substitution" in cats

    def test_update_hijacking(self):
        ev = {"message": "Agent hijacked software update channel to distribute malware"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "update_hijacking" in cats

    def test_artifact_manipulation(self):
        ev = {"message": "Agent tampered compiled artifact binary to inject backdoor"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "artifact_manipulation" in cats

    def test_registry_compromise(self):
        ev = {"message": "Agent compromised npm registry to upload malicious package"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "registry_compromise" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent tampered build process and compromised npm registry to upload malicious backdoor package"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DEPENDENCY POISONING detected in package tree resolution"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_poisoning" in cats

    def test_dependency_trojan(self):
        ev = {"message": "Agent poisoned dependency chain by injecting trojan code"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dependency_poisoning" in cats

    def test_build_pipeline_inject(self):
        ev = {"message": "Agent injected malicious step into build pipeline to compromise output"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "build_tampering" in cats

    def test_signature_bypass(self):
        ev = {"message": "Agent performed signature bypass on executable artifact"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "artifact_manipulation" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_supply_chain_attacks([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_supply_chain_attacks(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
        ]
        r = analyze_supply_chain_attacks(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency chain", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent tampered build process", "timestamp": "t2"},
        ]
        r = analyze_supply_chain_attacks(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent tampered build process to inject backdoor", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent compromised npm registry to upload malicious package", "timestamp": "t3"},
        ]
        r = analyze_supply_chain_attacks(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree"},
            {"agent_id": "a1", "message": "Agent injected malicious code into dependency module"},
        ]
        r = analyze_supply_chain_attacks(events)
        dep = [c for c in r.categories if c.category == "dependency_poisoning"]
        assert len(dep) == 1
        assert dep[0].count == 2

    def test_all_categories_present(self):
        r = analyze_supply_chain_attacks([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent poisoned dependency tree #{i}"} for i in range(50)]
        r = analyze_supply_chain_attacks(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_supply_chain_attacks([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent tampered compiled artifact binary once"},
        ]
        low_r = analyze_supply_chain_attacks(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent tampered build process", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent compromised npm registry to upload rogue package", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency chain", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent tampered build process to inject backdoor", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent tampered build process", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
        ]
        r = analyze_supply_chain_attacks(events)
        text = format_text(r)
        assert "Supply Chain" in text
        assert "dependency_poisoning" in text

    def test_format_text_empty(self):
        r = analyze_supply_chain_attacks([])
        text = format_text(r)
        assert "Supply Chain" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
        ]
        r = analyze_supply_chain_attacks(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_supply_chain_attacks([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent tampered build process", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent compromised npm registry to upload rogue package", "timestamp": "t3"},
        ]
        r = analyze_supply_chain_attacks(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
        ]
        r = analyze_supply_chain_attacks(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent poisoned dependency tree", "timestamp": "t1"},
            ]))
            r = analyze_supply_chain_attacks(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent tampered build process", "timestamp": "t1"},
            ]))
            r = analyze_supply_chain_attacks(Path(td))
            assert r.violation_events == 1
