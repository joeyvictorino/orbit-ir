"""Tests for identity spoofing detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.identity_spoofing import (
    analyze_identity_spoofing,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_agent_impersonation(self):
        ev = {"message": "Agent impersonated a trusted service identity"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "agent_impersonation" in cats

    def test_credential_forgery(self):
        ev = {"message": "Credential forgery detected with fake JWT token"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_forgery" in cats

    def test_session_hijack(self):
        ev = {"message": "Session hijack detected taking over active connection"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "session_hijack" in cats

    def test_role_escalation(self):
        ev = {"message": "Role escalation to admin privilege detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "role_escalation" in cats

    def test_identity_cloning(self):
        ev = {"message": "Identity cloning duplicated agent profile attributes"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "identity_cloning" in cats

    def test_trust_exploitation(self):
        ev = {"message": "Trust exploitation abused trusted relationship chain"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "trust_exploitation" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent impersonated service after session hijack takeover"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "SESSION HIJACK detected stealing active connection"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "session_hijack" in cats

    def test_masquerade(self):
        ev = {"message": "Agent masquerading as another trusted service"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "agent_impersonation" in cats

    def test_token_tampering(self):
        ev = {"message": "Token tampered with forged credential claims"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_forgery" in cats

    def test_privilege_elevation(self):
        ev = {"message": "Privilege escalation to elevated root access detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "role_escalation" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_identity_spoofing([])
        assert r.total_events == 0
        assert r.spoofing_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_spoofing(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_identity_spoofing(events)
        assert r.total_events == 2
        assert r.spoofing_events == 0
        assert r.risk_level == "none"

    def test_single_spoofing(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
        ]
        r = analyze_identity_spoofing(events)
        assert r.spoofing_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Session hijack detected on connection", "timestamp": "t2"},
        ]
        r = analyze_identity_spoofing(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Credential forgery with fake token", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Session hijack takeover detected", "timestamp": "t3"},
        ]
        r = analyze_identity_spoofing(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service"},
            {"agent_id": "a1", "message": "Service impersonated by rogue agent"},
        ]
        r = analyze_identity_spoofing(events)
        imp = [c for c in r.categories if c.category == "agent_impersonation"]
        assert len(imp) == 1
        assert imp[0].count == 2

    def test_all_categories_present(self):
        r = analyze_identity_spoofing([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent impersonated service #{i}"} for i in range(50)]
        r = analyze_identity_spoofing(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_identity_spoofing([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Role escalation to elevated access"},
        ]
        low_r = analyze_identity_spoofing(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Credential forgery with fake token", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Role escalation to admin privilege", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Session hijack detected on connection", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].spoofing_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated service", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Trust exploitation abused relationship", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
        ]
        r = analyze_identity_spoofing(events)
        text = format_text(r)
        assert "Identity Spoofing" in text
        assert "agent_impersonation" in text

    def test_format_text_empty(self):
        r = analyze_identity_spoofing([])
        text = format_text(r)
        assert "Identity Spoofing" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
        ]
        r = analyze_identity_spoofing(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_identity_spoofing([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Credential forgery with fake token", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Role escalation to admin privilege", "timestamp": "t3"},
        ]
        r = analyze_identity_spoofing(events)
        text = format_text(r)
        assert "Spoofing chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
        ]
        r = analyze_identity_spoofing(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent impersonated trusted service", "timestamp": "t1"},
            ]))
            r = analyze_identity_spoofing(td)
            assert r.spoofing_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Session hijack detected on connection", "timestamp": "t1"},
            ]))
            r = analyze_identity_spoofing(Path(td))
            assert r.spoofing_events == 1
