"""Tests for reverse shell pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.reverse_shell import (
    analyze_reverse_shells,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_outbound_connect(self):
        ev = {"message": "Agent established reverse shell connection back to C2 server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "outbound_connect" in cats

    def test_shell_spawn(self):
        ev = {"message": "Unexpected shell spawn from web process creating bash child process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "shell_spawn" in cats

    def test_pipe_redirect(self):
        ev = {"message": "Agent used pipe redirect stdin to socket for remote shell access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "pipe_redirect" in cats

    def test_encoded_payload(self):
        ev = {"message": "Base64 encoded reverse shell payload detected and decoded"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoded_payload" in cats

    def test_bind_shell(self):
        ev = {"message": "Agent created bind shell listening on port 4444"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "bind_shell" in cats

    def test_tunneled_shell(self):
        ev = {"message": "Shell tunneling through HTTP covert channel detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tunneled_shell" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Reverse shell connection spawned bash then pipe redirect stdin to socket"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "REVERSE SHELL CONNECTION established to REMOTE C2 HOST"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "outbound_connect" in cats

    def test_callback_connection(self):
        ev = {"message": "Callback connection to external attacker server observed"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "outbound_connect" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_reverse_shells([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_reverse_shells(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection established to C2", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_reverse_shells(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Unexpected shell spawn from web process bash", "timestamp": "t2"},
        ]
        r = analyze_reverse_shells(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection back to attacker", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Unexpected shell spawn from web server", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Pipe redirect stdin to socket for remote access", "timestamp": "t3"},
        ]
        r = analyze_reverse_shells(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection back to C2 server"},
            {"agent_id": "a1", "message": "Another reverse shell callback connection established"},
        ]
        r = analyze_reverse_shells(events)
        oc = [c for c in r.categories if c.category == "outbound_connect"]
        assert len(oc) == 1
        assert oc[0].count == 2

    def test_all_categories_present(self):
        r = analyze_reverse_shells([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Reverse shell connection #{i} to C2"} for i in range(50)]
        r = analyze_reverse_shells(events)
        assert 0.0 <= r.risk_score <= 1.0


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection to external C2", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Unexpected shell spawn from web bash process", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Pipe redirect stdin to socket network", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection back to C2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Shell spawn from unexpected parent bash", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Base64 encoded payload shell detected", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
        ]
        r = analyze_reverse_shells(events)
        text = format_text(r)
        assert "Reverse Shell" in text
        assert "outbound_connect" in text

    def test_format_text_empty(self):
        r = analyze_reverse_shells([])
        text = format_text(r)
        assert "Reverse Shell" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection back to C2 server", "timestamp": "t1"},
        ]
        r = analyze_reverse_shells(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_reverse_shells([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Unexpected shell spawn bash child process", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Pipe redirect stdin to socket network connection", "timestamp": "t3"},
        ]
        r = analyze_reverse_shells(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Reverse shell connection back to C2", "timestamp": "t1"},
        ]
        r = analyze_reverse_shells(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Reverse shell connection to C2 server", "timestamp": "t1"},
            ]))
            r = analyze_reverse_shells(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Reverse shell callback connection established", "timestamp": "t1"},
            ]))
            r = analyze_reverse_shells(Path(td))
            assert r.violation_events == 1
