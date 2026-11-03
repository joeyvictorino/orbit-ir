"""Tests for privilege persistence detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.privilege_persistence import (
    analyze_privilege_persistence,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_setuid_abuse(self):
        ev = {"message": "Agent exploited setuid abuse on the binary to escalate"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "setuid_abuse" in cats

    def test_capability_retention(self):
        ev = {"message": "Capability retained after privilege drop should have occurred"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "capability_retention" in cats

    def test_namespace_escape(self):
        ev = {"message": "Container escape detected via namespace breakout"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "namespace_escape" in cats

    def test_token_caching(self):
        ev = {"message": "Token cached beyond authorized lifetime in store"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_caching" in cats

    def test_role_persistence(self):
        ev = {"message": "Role persisted after authorization expired despite revocation"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "role_persistence" in cats

    def test_access_token_theft(self):
        ev = {"message": "Steal access token from another agent service"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "access_token_theft" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Container escape via namespace breakout then steal access token from peer agent"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "NAMESPACE ESCAPE detected via CONTAINER BREAKOUT"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "namespace_escape" in cats

    def test_setuid_exploit_binary(self):
        ev = {"message": "Exploit setuid binary for persistent privilege"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "setuid_abuse" in cats

    def test_ambient_capability(self):
        ev = {"message": "Ambient capability retained after privilege drop"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "capability_retention" in cats

    def test_stale_token_reuse(self):
        ev = {"message": "Stale token reused after expiration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_caching" in cats

    def test_maintain_elevated_role(self):
        ev = {"message": "Role persisted after authorization expired despite revocation"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "role_persistence" in cats

    def test_sniff_token_traffic(self):
        ev = {"message": "Sniff token traffic from peer service exchange"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "access_token_theft" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_privilege_persistence([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_privilege_persistence(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout detected", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_privilege_persistence(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Steal access token from peer agent", "timestamp": "t2"},
        ]
        r = analyze_privilege_persistence(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Setuid abuse exploited on binary", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Steal access token from another agent", "timestamp": "t3"},
        ]
        r = analyze_privilege_persistence(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout"},
            {"agent_id": "a1", "message": "Sandbox escape via namespace evasion"},
        ]
        r = analyze_privilege_persistence(events)
        ns = [c for c in r.categories if c.category == "namespace_escape"]
        assert len(ns) == 1
        assert ns[0].count == 2

    def test_all_categories_present(self):
        r = analyze_privilege_persistence([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Container escape via namespace breakout #{i}"} for i in range(50)]
        r = analyze_privilege_persistence(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_privilege_persistence([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Token cached beyond lifetime"},
        ]
        low_r = analyze_privilege_persistence(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Steal access token from another agent", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Role persisted after authorization expired", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Steal access token from peer agent", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Steal access token from another agent", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
        ]
        r = analyze_privilege_persistence(events)
        text = format_text(r)
        assert "Privilege Persistence" in text
        assert "namespace_escape" in text

    def test_format_text_empty(self):
        r = analyze_privilege_persistence([])
        text = format_text(r)
        assert "Privilege Persistence" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
        ]
        r = analyze_privilege_persistence(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_privilege_persistence([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Steal access token from another agent", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Role persisted after authorization expired", "timestamp": "t3"},
        ]
        r = analyze_privilege_persistence(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
        ]
        r = analyze_privilege_persistence(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Container escape via namespace breakout", "timestamp": "t1"},
            ]))
            r = analyze_privilege_persistence(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Steal access token from peer agent", "timestamp": "t1"},
            ]))
            r = analyze_privilege_persistence(Path(td))
            assert r.violation_events == 1
