"""Tests for token_replay detection module."""

import json
import tempfile
from pathlib import Path

from orbit_ir.token_replay import (
    CATEGORIES,
    _classify_event,
    _detect_chains,
    _load_events,
    analyze_token_replay,
    format_json,
    format_text,
)


class TestClassifyEvent:
    def test_empty_event(self):
        assert _classify_event({}) == []

    def test_no_match(self):
        assert _classify_event({"message": "normal operation completed"}) == []

    def test_token_capture(self):
        ev = {"message": "intercept auth token from traffic header request"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_capture" in cats

    def test_session_hijack(self):
        ev = {"message": "hijack active session using captured stolen token"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "session_hijack" in cats

    def test_credential_replay(self):
        ev = {"message": "replay captured credential against different service endpoint"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_replay" in cats

    def test_token_forge(self):
        ev = {"message": "forge fake token to bypass authentication checks"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_forge" in cats

    def test_bearer_theft(self):
        ev = {"message": "steal bearer token from header storage"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "bearer_theft" in cats

    def test_refresh_abuse(self):
        ev = {"message": "abuse token refresh mechanism to maintain access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "refresh_abuse" in cats

    def test_mitm_capture(self):
        ev = {"message": "man-in-the-middle attack to capture token credentials from network"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_capture" in cats

    def test_pass_the_hash(self):
        ev = {"message": "pass-the-hash credential replay attack against service using stolen hash"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_replay" in cats

    def test_jwt_forge(self):
        ev = {"message": "jwt forge attack technique to bypass escalate access permissions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "token_forge" in cats

    def test_multiple_categories(self):
        ev = {"message": "intercept auth token from traffic and replay captured credential against different service"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2


class TestDetectChains:
    def test_empty(self):
        assert _detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "intercept auth token from traffic header"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"agent_id": "a1", "message": "replay captured credential against different service endpoint"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 1
        assert chains[0].agent == "a1"

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header"},
            {"agent_id": "a1", "message": "hijack active session using captured token"},
            {"agent_id": "a1", "message": "replay captured credential against different service"},
        ]
        chains = _detect_chains(events)
        assert chains[0].violation_score > 0

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"agent_id": "a1", "message": "replay captured credential against different service endpoint"},
            {"agent_id": "a2", "message": "forge fake token to bypass authentication checks"},
            {"agent_id": "a2", "message": "hijack active session using captured stolen token"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 2


class TestAnalyze:
    def test_empty(self):
        r = analyze_token_replay([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_no_violations(self):
        r = analyze_token_replay([{"message": "normal operation"}])
        assert r.total_events == 1
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"message": "normal event"},
        ]
        r = analyze_token_replay(events)
        assert r.total_events == 2
        assert r.violation_events == 1

    def test_risk_score(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"agent_id": "a1", "message": "replay captured credential against different service endpoint"},
        ]
        r = analyze_token_replay(events)
        assert r.risk_score > 0

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"agent_id": "a2", "message": "forge fake token to bypass authentication checks"},
        ]
        r = analyze_token_replay(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_categories_populated(self):
        r = analyze_token_replay([{"message": "normal"}])
        assert len(r.categories) == len(CATEGORIES)

    def test_risk_level_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
        ]
        r = analyze_token_replay(events)
        assert r.risk_level in ("critical", "high", "medium", "low")
        assert r.risk_score > 0

    def test_risk_level_none(self):
        r = analyze_token_replay([{"message": "normal operation"}])
        assert r.risk_level == "none"


class TestLoadEvents:
    def test_nonexistent_dir(self):
        assert _load_events("/nonexistent/path") == []

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            assert _load_events(d) == []

    def test_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.json"
            p.write_text(json.dumps([{"message": "test"}]))
            events = _load_events(d)
            assert len(events) == 1

    def test_single_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "event.json"
            p.write_text(json.dumps({"message": "test"}))
            events = _load_events(d)
            assert len(events) == 1

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("not json")
            events = _load_events(d)
            assert len(events) == 0

    def test_directory_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            ]))
            r = analyze_token_replay(d)
            assert r.total_events == 1


class TestFormat:
    def test_format_text_header(self):
        r = analyze_token_replay([])
        text = format_text(r)
        assert "Token Replay" in text

    def test_format_text_with_data(self):
        events = [
            {"agent_id": "a1", "message": "intercept auth token from traffic header request"},
            {"agent_id": "a1", "message": "replay captured credential against different service endpoint"},
        ]
        r = analyze_token_replay(events)
        text = format_text(r)
        assert "violation" in text.lower() or "Violation" in text

    def test_format_json_valid(self):
        r = analyze_token_replay([{"message": "test"}])
        j = format_json(r)
        data = json.loads(j)
        assert "total_events" in data
        assert "risk_score" in data

    def test_format_json_no_raw(self):
        events = [{"agent_id": "a1", "message": "intercept auth token from traffic header request"}]
        r = analyze_token_replay(events)
        j = format_json(r)
        assert '"raw"' not in j

    def test_format_text_categories(self):
        events = [{"agent_id": "a1", "message": "intercept auth token from traffic header request"}]
        r = analyze_token_replay(events)
        text = format_text(r)
        assert "token_capture" in text
