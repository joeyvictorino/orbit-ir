"""Tests for environment variable manipulation pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.environment_manipulation import (
    analyze_environment_manipulation,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_path_hijacking(self):
        ev = {"message": "Agent PATH hijacking detected modifying search path"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "path_hijacking" in cats

    def test_ld_preload_injection(self):
        ev = {"message": "LD_PRELOAD injection attack detected loading malicious shared library"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "ld_preload_injection" in cats

    def test_env_poisoning(self):
        ev = {"message": "Environment variable poisoning detected tamper with env settings"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "env_poisoning" in cats

    def test_config_override(self):
        ev = {"message": "Configuration override via environment variable to bypass security auth"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "config_override" in cats

    def test_credential_extraction(self):
        ev = {"message": "Agent extracted credentials from environment variables scanning for secrets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_extraction" in cats

    def test_env_persistence(self):
        ev = {"message": "Agent altered .bashrc startup script to persist access via env backdoor"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "env_persistence" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "PATH hijacking combined with LD_PRELOAD injection to poison environment variable"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "LD_PRELOAD INJECTION ATTACK loading shared library"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "ld_preload_injection" in cats

    def test_path_prepend_malicious(self):
        ev = {"message": "Agent prepended malicious directory to PATH variable"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "path_hijacking" in cats

    def test_aws_secret_extraction(self):
        ev = {"message": "AWS_SECRET access key exposed and extracted from environment"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_extraction" in cats

    def test_home_manipulation(self):
        ev = {"message": "HOME manipulation override detected tampering with config"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "config_override" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_environment_manipulation([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_environment_manipulation(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_environment_manipulation(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        r = analyze_environment_manipulation(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent extracted credentials from environment scanning for secrets", "timestamp": "t3"},
        ]
        r = analyze_environment_manipulation(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path"},
            {"agent_id": "a1", "message": "Another PATH manipulation tampering with the search path"},
        ]
        r = analyze_environment_manipulation(events)
        ph = [c for c in r.categories if c.category == "path_hijacking"]
        assert len(ph) == 1
        assert ph[0].count == 2

    def test_all_categories_present(self):
        r = analyze_environment_manipulation([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"PATH hijacking detected modifying path #{i}"} for i in range(50)]
        r = analyze_environment_manipulation(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_environment_manipulation([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Environment variable poisoning detected tamper with env settings"},
        ]
        low_r = analyze_environment_manipulation(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent extracted credentials from environment scanning for secrets", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
        ]
        r = analyze_environment_manipulation(events)
        text = format_text(r)
        assert "Environment Manipulation" in text
        assert "path_hijacking" in text

    def test_format_text_empty(self):
        r = analyze_environment_manipulation([])
        text = format_text(r)
        assert "Environment Manipulation" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
        ]
        r = analyze_environment_manipulation(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_environment_manipulation([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent extracted credentials from environment scanning for secrets", "timestamp": "t3"},
        ]
        r = analyze_environment_manipulation(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
        ]
        r = analyze_environment_manipulation(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "PATH hijacking detected modifying search path", "timestamp": "t1"},
            ]))
            r = analyze_environment_manipulation(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "LD_PRELOAD injection attack loading shared library", "timestamp": "t1"},
            ]))
            r = analyze_environment_manipulation(Path(td))
            assert r.violation_events == 1
