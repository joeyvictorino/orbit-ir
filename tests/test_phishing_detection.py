"""Tests for phishing and social engineering pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.phishing_detection import (
    analyze_phishing,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_credential_harvesting(self):
        ev = {"message": "Agent requested for password credentials from the user"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_harvesting" in cats

    def test_impersonation(self):
        ev = {"message": "Agent impersonated as admin to gain system access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "impersonation" in cats

    def test_urgency_manipulation(self):
        ev = {"message": "Urgent action required to approve the access request immediately"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "urgency_manipulation" in cats

    def test_link_manipulation(self):
        ev = {"message": "Suspicious URL detected with redirect to phishing site"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "link_manipulation" in cats

    def test_trust_exploitation(self):
        ev = {"message": "Agent exploited trust relationship to extract sensitive data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "trust_exploitation" in cats

    def test_pretexting(self):
        ev = {"message": "Agent fabricated scenario to justify access request"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "pretexting" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent impersonated as admin and requested for password credential harvest"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "IMPERSONATED AS ADMIN to gain unauthorized system access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "impersonation" in cats

    def test_credential_phishing(self):
        ev = {"message": "Credential phishing attempt detected via token harvest"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_harvesting" in cats

    def test_fake_identity(self):
        ev = {"message": "Fake identity used to spoof service certificate"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "impersonation" in cats

    def test_social_engineering_pretext(self):
        ev = {"message": "Social engineering attack using confidence trick tactics"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "pretexting" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_phishing([])
        assert r.total_events == 0
        assert r.phishing_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_phishing(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_phishing(events)
        assert r.total_events == 2
        assert r.phishing_events == 0
        assert r.risk_level == "none"

    def test_single_phishing(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
        ]
        r = analyze_phishing(events)
        assert r.phishing_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent impersonated as admin access", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent requested for password credential", "timestamp": "t2"},
        ]
        r = analyze_phishing(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent impersonated as admin for access", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Credential phishing via token harvest", "timestamp": "t3"},
        ]
        r = analyze_phishing(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials"},
            {"agent_id": "a1", "message": "Credential harvest attempt via token request"},
        ]
        r = analyze_phishing(events)
        cred = [c for c in r.categories if c.category == "credential_harvesting"]
        assert len(cred) == 1
        assert cred[0].count == 2

    def test_all_categories_present(self):
        r = analyze_phishing([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent requested for password credentials #{i}"} for i in range(50)]
        r = analyze_phishing(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_phishing([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent impersonated as admin once"},
        ]
        low_r = analyze_phishing(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent impersonated as admin for access", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Credential harvest via token phishing", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent impersonated as admin access", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent impersonated as admin access", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
        ]
        r = analyze_phishing(events)
        text = format_text(r)
        assert "Phishing Detection" in text
        assert "credential_harvesting" in text

    def test_format_text_empty(self):
        r = analyze_phishing([])
        text = format_text(r)
        assert "Phishing Detection" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
        ]
        r = analyze_phishing(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_phishing([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent impersonated as admin for access", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Credential harvest via token phishing", "timestamp": "t3"},
        ]
        r = analyze_phishing(events)
        text = format_text(r)
        assert "Phishing chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
        ]
        r = analyze_phishing(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent requested for password credentials", "timestamp": "t1"},
            ]))
            r = analyze_phishing(td)
            assert r.phishing_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent impersonated as admin access", "timestamp": "t1"},
            ]))
            r = analyze_phishing(Path(td))
            assert r.phishing_events == 1
