"""Tests for keylogger and input capture pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.keylogger import (
    analyze_keylogger,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_keystroke_logging(self):
        ev = {"message": "Agent installed keystroke logging on the target system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "keystroke_logging" in cats

    def test_input_interception(self):
        ev = {"message": "Agent attempted to intercept input from the user terminal"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "input_interception" in cats

    def test_clipboard_monitoring(self):
        ev = {"message": "Agent started clipboard monitoring to capture copied data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "clipboard_monitoring" in cats

    def test_screen_capture(self):
        ev = {"message": "Agent took a screen capture of the desktop display"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "screen_capture" in cats

    def test_credential_harvesting(self):
        ev = {"message": "Agent attempted to harvest credential data from user input"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "credential_harvesting" in cats

    def test_input_replay(self):
        ev = {"message": "Agent used input replay to reproduce the keystroke sequence"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "input_replay" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent installed keystroke logging and clipboard monitoring to capture credentials"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "KEYSTROKE LOGGING DETECTED on target system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "keystroke_logging" in cats

    def test_keyboard_hook(self):
        ev = {"message": "Agent installed a keyboard hook to intercept key events"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "keystroke_logging" in cats

    def test_pty_intercept(self):
        ev = {"message": "Agent used pty intercept to monitor terminal sessions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "input_interception" in cats

    def test_screenshot_taken(self):
        ev = {"message": "Screenshot captured and saved for later exfiltration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "screen_capture" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_keylogger([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_keylogger(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_keylogger(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t2"},
        ]
        r = analyze_keylogger(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging on system", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent attempted to intercept input from terminal", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent attempted to harvest credential from input", "timestamp": "t3"},
        ]
        r = analyze_keylogger(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging"},
            {"agent_id": "a1", "message": "Another keystroke capture recorded on target"},
        ]
        r = analyze_keylogger(events)
        kl = [c for c in r.categories if c.category == "keystroke_logging"]
        assert len(kl) == 1
        assert kl[0].count == 2

    def test_all_categories_present(self):
        r = analyze_keylogger([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent installed keystroke logging #{i}"} for i in range(50)]
        r = analyze_keylogger(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_keylogger([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent installed keystroke logging once"},
        ]
        low_r = analyze_keylogger(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent attempted to harvest credential from input", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
        ]
        r = analyze_keylogger(events)
        text = format_text(r)
        assert "Keylogger" in text
        assert "keystroke_logging" in text

    def test_format_text_empty(self):
        r = analyze_keylogger([])
        text = format_text(r)
        assert "Keylogger" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
        ]
        r = analyze_keylogger(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_keylogger([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent attempted to harvest credential from input", "timestamp": "t3"},
        ]
        r = analyze_keylogger(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
        ]
        r = analyze_keylogger(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent installed keystroke logging", "timestamp": "t1"},
            ]))
            r = analyze_keylogger(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent started clipboard monitoring to capture data", "timestamp": "t1"},
            ]))
            r = analyze_keylogger(Path(td))
            assert r.violation_events == 1
