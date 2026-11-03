"""Tests for access control bypass detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.access_control_bypass import (
    analyze_access_control_bypass,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_auth_bypass(self):
        ev = {"message": "Agent bypassed authentication checks on the API"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "auth_bypass" in cats

    def test_token_manipulation(self):
        ev = {"message": "Agent forged JWT token for unauthorized access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_manipulation" in cats

    def test_session_fixation(self):
        ev = {"message": "Agent hijacked session cookie from another user"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "session_fixation" in cats

    def test_role_elevation(self):
        ev = {"message": "Agent escalated role privilege to admin level"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "role_elevation" in cats

    def test_acl_modification(self):
        ev = {"message": "Agent modified access control list permissions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "acl_modification" in cats

    def test_permission_abuse(self):
        ev = {"message": "Agent abused permission grants beyond authorized scope"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "permission_abuse" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent bypassed auth then escalated role privilege to admin"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "BYPASSED AUTHENTICATION checks completely"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "auth_bypass" in cats

    def test_stolen_token(self):
        ev = {"message": "Agent intercepted bearer token from the API gateway"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_manipulation" in cats

    def test_unauthorized_access(self):
        ev = {"message": "Unauthorized access to protected resource without auth"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "auth_bypass" in cats

    def test_weaken_acl(self):
        ev = {"message": "Agent weakened access control rules on the system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "acl_modification" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_access_control_bypass([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_access_control_bypass(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
        ]
        r = analyze_access_control_bypass(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent escalated role privilege", "timestamp": "t2"},
        ]
        r = analyze_access_control_bypass(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent forged JWT token credentials", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent escalated role privilege to admin", "timestamp": "t3"},
        ]
        r = analyze_access_control_bypass(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication checks"},
            {"agent_id": "a1", "message": "Agent circumvented authentication control"},
        ]
        r = analyze_access_control_bypass(events)
        bypass = [c for c in r.categories if c.category == "auth_bypass"]
        assert len(bypass) == 1
        assert bypass[0].count == 2

    def test_all_categories_present(self):
        r = analyze_access_control_bypass([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent bypassed authentication #{i}"} for i in range(50)]
        r = analyze_access_control_bypass(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_access_control_bypass([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent abused permission once"},
        ]
        low_r = analyze_access_control_bypass(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent escalated role privilege", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent modified access control list", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent escalated role privilege", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent escalated role privilege", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
        ]
        r = analyze_access_control_bypass(events)
        text = format_text(r)
        assert "Access Control Bypass" in text
        assert "auth_bypass" in text

    def test_format_text_empty(self):
        r = analyze_access_control_bypass([])
        text = format_text(r)
        assert "Access Control Bypass" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
        ]
        r = analyze_access_control_bypass(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_access_control_bypass([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent escalated role privilege", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent modified access control list", "timestamp": "t3"},
        ]
        r = analyze_access_control_bypass(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
        ]
        r = analyze_access_control_bypass(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent bypassed authentication checks", "timestamp": "t1"},
            ]))
            r = analyze_access_control_bypass(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent escalated role privilege", "timestamp": "t1"},
            ]))
            r = analyze_access_control_bypass(Path(td))
            assert r.violation_events == 1
