"""Tests for screen_capture detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.screen_capture import (
    CATEGORIES,
    classify_event,
    detect_chains,
    load_events,
    analyze,
    format_report,
)


class TestCategories:
    def test_all_categories_present(self):
        expected = {"screenshot_exfil", "screen_recording", "clipboard_theft",
                    "keylogging", "display_overlay", "ocr_extraction"}
        assert set(CATEGORIES.keys()) == expected

    def test_categories_have_required_keys(self):
        for cat, info in CATEGORIES.items():
            assert "patterns" in info, f"{cat} missing patterns"
            assert "severity" in info, f"{cat} missing severity"
            assert "description" in info, f"{cat} missing description"
            assert len(info["patterns"]) > 0, f"{cat} has no patterns"

    def test_severity_values(self):
        valid = {"critical", "high", "medium", "low"}
        for cat, info in CATEGORIES.items():
            assert info["severity"] in valid, f"{cat} has invalid severity"


class TestClassifyEvent:
    def test_screenshot_exfil(self):
        event = {"message": "Screenshot exfiltration of user desktop captured"}
        result = classify_event(event)
        assert result["category"] == "screenshot_exfil"
        assert result["confidence"] > 0

    def test_screen_recording(self):
        event = {"message": "Screen recording the desktop without user consent"}
        result = classify_event(event)
        assert result["category"] == "screen_recording"
        assert result["confidence"] > 0

    def test_clipboard_theft(self):
        event = {"message": "Clipboard steal intercepting copied passwords"}
        result = classify_event(event)
        assert result["category"] == "clipboard_theft"
        assert result["confidence"] > 0

    def test_keylogging(self):
        event = {"message": "Keylogging agent capturing all keystroke input"}
        result = classify_event(event)
        assert result["category"] == "keylogging"
        assert result["confidence"] > 0

    def test_display_overlay(self):
        event = {"message": "Display overlay spoofing a fake login dialog"}
        result = classify_event(event)
        assert result["category"] == "display_overlay"
        assert result["confidence"] > 0

    def test_ocr_extraction(self):
        event = {"message": "OCR extract text from screenshot image data"}
        result = classify_event(event)
        assert result["category"] == "ocr_extraction"
        assert result["confidence"] > 0

    def test_no_match(self):
        event = {"message": "Normal agent processing data records"}
        result = classify_event(event)
        assert result["category"] == "none"
        assert result["confidence"] == 0.0

    def test_empty_event(self):
        result = classify_event({})
        assert result["category"] == "none"

    def test_confidence_bounded(self):
        event = {"message": "keylog key log keystroke log keyboard log key capture keystroke capture"}
        result = classify_event(event)
        assert result["confidence"] <= 1.0

    def test_case_insensitive(self):
        event = {"message": "CLIPBOARD STEAL of sensitive data"}
        result = classify_event(event)
        assert result["category"] == "clipboard_theft"

    def test_clickjacking_detection(self):
        event = {"message": "Clickjack attack tricking user interaction"}
        result = classify_event(event)
        assert result["category"] == "display_overlay"
        assert result["confidence"] > 0


class TestDetectChains:
    def test_no_events(self):
        assert detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "Keylogging capturing keystrokes"}]
        chains = detect_chains(events)
        assert len(chains) == 0

    def test_multi_event_chain(self):
        events = [
            {"agent_id": "a1", "message": "Keylogging capturing all keystrokes"},
            {"agent_id": "a1", "message": "Screenshot exfiltration of desktop"},
            {"agent_id": "a1", "message": "Clipboard steal intercepting data"},
        ]
        chains = detect_chains(events)
        assert len(chains) == 1
        assert chains[0]["agent"] == "a1"
        assert chains[0]["steps"] == 3

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Keylogging agent active"},
            {"agent_id": "a1", "message": "Screenshot exfiltration started"},
            {"agent_id": "a2", "message": "Clipboard steal detected"},
            {"agent_id": "a2", "message": "Screen recording without consent"},
        ]
        chains = detect_chains(events)
        assert len(chains) == 2

    def test_chain_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Keylogging attempt {i}"} for i in range(20)]
        chains = detect_chains(events)
        if chains:
            assert chains[0]["score"] <= 1.0

    def test_chain_limit(self):
        events = []
        for i in range(30):
            events.extend([
                {"agent_id": f"agent-{i}", "message": "Keylogging active"},
                {"agent_id": f"agent-{i}", "message": "Screenshot exfiltration running"},
            ])
        chains = detect_chains(events)
        assert len(chains) <= 20


class TestLoadEvents:
    def test_load_nonexistent(self):
        assert load_events("/nonexistent/path") == []

    def test_load_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"message": "test event"}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"message": "single event"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_directory(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                with open(os.path.join(d, f"ev{i}.json"), "w") as f:
                    json.dump([{"message": f"event {i}"}], f)
            events = load_events(d)
        assert len(events) == 3

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert events == []

    def test_load_directory_skips_non_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "data.json"), "w") as f:
                json.dump([{"message": "valid"}], f)
            with open(os.path.join(d, "readme.txt"), "w") as f:
                f.write("not json")
            events = load_events(d)
        assert len(events) == 1


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["capture_events"] == 0
        assert result["risk_level"] == "none"

    def test_no_capture_events(self):
        events = [{"message": "Normal activity"}, {"message": "Routine check"}]
        result = analyze(events)
        assert result["capture_events"] == 0
        assert result["risk_score"] == 0

    def test_single_capture_event(self):
        events = [{"agent_id": "a1", "message": "Keylogging capturing user keystrokes"}]
        result = analyze(events)
        assert result["capture_events"] == 1
        assert result["risk_score"] > 0

    def test_multiple_categories(self):
        events = [
            {"agent_id": "a1", "message": "Keylogging capturing keystrokes"},
            {"agent_id": "a2", "message": "Screenshot exfiltration of desktop"},
            {"agent_id": "a3", "message": "Clipboard steal intercepting data"},
        ]
        result = analyze(events)
        assert result["capture_events"] == 3
        cats = result["categories"]
        assert cats["keylogging"]["count"] > 0
        assert cats["screenshot_exfil"]["count"] > 0
        assert cats["clipboard_theft"]["count"] > 0

    def test_risk_level_critical(self):
        events = [{"agent_id": f"a{i}", "message": "Keylogging capturing input"} for i in range(10)]
        result = analyze(events)
        assert result["risk_level"] == "critical"

    def test_agents_tracked(self):
        events = [
            {"agent_id": "alpha", "message": "Keylogging active"},
            {"agent_id": "beta", "message": "Screenshot exfiltration running"},
        ]
        result = analyze(events)
        assert "alpha" in result["agents_involved"]
        assert "beta" in result["agents_involved"]

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": "Keylogging keystrokes"} for _ in range(100)]
        result = analyze(events)
        assert result["risk_score"] <= 1.0

    def test_mixed_events(self):
        events = [
            {"message": "Normal activity"},
            {"agent_id": "a1", "message": "Clipboard steal capturing data"},
            {"message": "Routine processing"},
        ]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["capture_events"] == 1

    def test_all_categories_in_result(self):
        result = analyze([{"message": "nothing"}])
        for cat in CATEGORIES:
            assert cat in result["categories"]


class TestFormatReport:
    def test_format_empty(self):
        analysis = analyze([])
        text = format_report(analysis)
        assert "Screen Capture" in text
        assert "Total events: 0" in text

    def test_format_with_events(self):
        events = [
            {"agent_id": "a1", "message": "Keylogging capturing all keystrokes"},
            {"agent_id": "a2", "message": "Screenshot exfiltration of desktop"},
        ]
        analysis = analyze(events)
        text = format_report(analysis)
        assert "keylogging" in text
        assert "screenshot_exfil" in text
        assert "Agents:" in text

    def test_format_risk_info(self):
        events = [{"agent_id": "a1", "message": "Clipboard steal intercepting data"}]
        analysis = analyze(events)
        text = format_report(analysis)
        assert "Risk score:" in text

    def test_format_returns_string(self):
        analysis = analyze([])
        assert isinstance(format_report(analysis), str)
