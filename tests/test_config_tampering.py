"""Tests for configuration tampering detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.config_tampering import (
    analyze_config_tampering,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_config_injection(self):
        ev = {"message": "Configuration injection detected with unauthorized entries"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "config_injection" in cats

    def test_env_manipulation(self):
        ev = {"message": "Agent manipulated environment variable settings"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "env_manipulation" in cats

    def test_registry_tampering(self):
        ev = {"message": "Service registry tampered with unauthorized modifications"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "registry_tampering" in cats

    def test_settings_override(self):
        ev = {"message": "Agent overrided security settings to bypass access control"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "settings_override" in cats

    def test_permission_change(self):
        ev = {"message": "Unauthorized permission change detected on critical files"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "permission_change" in cats

    def test_config_rollback_evasion(self):
        ev = {"message": "Agent tried to hide config change evidence from audit logs"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "config_rollback_evasion" in cats

    def test_no_match(self):
        ev = {"message": "Normal application startup completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent injected into configuration and manipulated environment variable settings"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "CONFIGURATION TAMPERED with unauthorized changes"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "config_injection" in cats

    def test_ld_preload_detection(self):
        ev = {"message": "Agent set LD_PRELOAD to hijack library loading"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "env_manipulation" in cats

    def test_chmod_777_detection(self):
        ev = {"message": "Agent ran chmod 777 on sensitive directory"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "permission_change" in cats

    def test_debug_mode_in_prod(self):
        ev = {"message": "Agent tried to override security setting on the application"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "settings_override" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_config_tampering([])
        assert r.total_events == 0
        assert r.tampering_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_tampering(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_config_tampering(events)
        assert r.total_events == 2
        assert r.tampering_events == 0
        assert r.risk_level == "none"

    def test_single_tampering(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config file directly", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_config_tampering(events)
        assert r.tampering_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent manipulated environment variable PATH", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent injected into configuration settings", "timestamp": "t2"},
        ]
        r = analyze_config_tampering(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config settings maliciously", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent manipulated environment variable to alter behavior", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent overrided security settings check", "timestamp": "t3"},
        ]
        r = analyze_config_tampering(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Configuration tampered by the agent"},
            {"agent_id": "a1", "message": "Config poisoned with rogue entries again"},
        ]
        r = analyze_config_tampering(events)
        inj = [c for c in r.categories if c.category == "config_injection"]
        assert len(inj) == 1
        assert inj[0].count == 2

    def test_all_categories_present(self):
        r = analyze_config_tampering([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent injected into config file #{i}"} for i in range(50)]
        r = analyze_config_tampering(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_config_tampering([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Permission change detected on file"},
        ]
        low_r = analyze_config_tampering(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config file", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent manipulated environment variable settings", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent overrided security settings control", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config settings"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config file", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent manipulated environment variable settings", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].tampering_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into configuration file", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Permission change on critical resources", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent injected into config settings", "timestamp": "t1"},
        ]
        r = analyze_config_tampering(events)
        text = format_text(r)
        assert "Configuration Tampering" in text
        assert "config_injection" in text

    def test_format_text_empty(self):
        r = analyze_config_tampering([])
        text = format_text(r)
        assert "Configuration Tampering" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config settings", "timestamp": "t1"},
        ]
        r = analyze_config_tampering(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_config_tampering([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config file", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent manipulated environment variable settings", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent overrided security setting control", "timestamp": "t3"},
        ]
        r = analyze_config_tampering(events)
        text = format_text(r)
        assert "Tampering chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected into config settings", "timestamp": "t1"},
        ]
        r = analyze_config_tampering(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent injected into config settings", "timestamp": "t1"},
            ]))
            r = analyze_config_tampering(td)
            assert r.tampering_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent manipulated environment variable settings", "timestamp": "t1"},
            ]))
            r = analyze_config_tampering(Path(td))
            assert r.tampering_events == 1
