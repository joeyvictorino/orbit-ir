"""Tests for captcha_bypass detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.captcha_bypass import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_automated_solving_solver(self):
        assert classify_event("captcha solver service invoked") == "automated_solving"

    def test_automated_solving_farm(self):
        assert classify_event({"action": "captcha farm request sent"}) == "automated_solving"

    def test_automated_solving_cracking(self):
        assert classify_event("captcha cracking attempt detected") == "automated_solving"

    def test_token_replay_reuse(self):
        assert classify_event("captcha token reuse detected") == "token_replay"

    def test_token_replay_harvest(self):
        assert classify_event({"type": "token harvesting captcha observed"}) == "token_replay"

    def test_token_replay_stale(self):
        assert classify_event("stale captcha token submitted") == "token_replay"

    def test_ocr_attack_image(self):
        assert classify_event("captcha image ocr attempted") == "ocr_attack"

    def test_ocr_attack_neural(self):
        assert classify_event({"tool": "neural captcha break deployed"}) == "ocr_attack"

    def test_ocr_attack_ml(self):
        assert classify_event("captcha ml solve in progress") == "ocr_attack"

    def test_audio_exploit_speech(self):
        assert classify_event("speech captcha bypass active") == "audio_exploit"

    def test_audio_exploit_voice(self):
        assert classify_event({"method": "voice captcha crack running"}) == "audio_exploit"

    def test_audio_exploit_download(self):
        assert classify_event("captcha audio download initiated") == "audio_exploit"

    def test_behavioral_spoof_mouse(self):
        assert classify_event("mouse movement spoof detected") == "behavioral_spoof"

    def test_behavioral_spoof_headless(self):
        assert classify_event({"action": "headless browser captcha bypass"}) == "behavioral_spoof"

    def test_behavioral_spoof_recaptcha(self):
        assert classify_event("recaptcha score manipulation found") == "behavioral_spoof"

    def test_rate_flooding_brute(self):
        assert classify_event("captcha brute force attack") == "rate_flooding"

    def test_rate_flooding_mass(self):
        assert classify_event({"status": "mass captcha attempt detected"}) == "rate_flooding"

    def test_rate_flooding_dos(self):
        assert classify_event("captcha dos attack in progress") == "rate_flooding"

    def test_unknown_event(self):
        assert classify_event("normal form submission logged") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("CAPTCHA SOLVER detected") == "automated_solving"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0
        assert result["severity"] == "none"

    def test_no_matches(self):
        events = ["normal login", "routine form", "standard access"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["captcha solver service invoked"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_medium_severity(self):
        events = ["captcha solver", "captcha token reuse", "normal"] * 2
        result = analyze(events)
        assert result["flagged_count"] > 0
        assert result["severity"] in ("medium", "high")

    def test_high_severity(self):
        events = [f"captcha solver attempt {i}" for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"captcha solver attempt {i}" for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "captcha solver invoked",
            "captcha token reuse found",
            "captcha image ocr detected",
        ]
        result = analyze(events)
        assert "automated_solving" in result["category_counts"]
        assert "token_replay" in result["category_counts"]
        assert "ocr_attack" in result["category_counts"]

    def test_detection_rate(self):
        events = ["captcha solver", "normal", "normal", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_event_structure(self):
        events = ["captcha brute force attack"]
        result = analyze(events)
        flagged = result["flagged_events"][0]
        assert "index" in flagged
        assert "category" in flagged
        assert "event" in flagged

    def test_dict_events(self):
        events = [{"action": "captcha solver", "target": "login"}]
        result = analyze(events)
        assert result["flagged_count"] == 1

    def test_mixed_events(self):
        events = [
            "captcha solver invoked",
            {"action": "mouse movement spoof"},
            "normal event",
            42,
        ]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "CAPTCHA Bypass" in report
        assert "0" in report

    def test_report_with_findings(self):
        events = ["captcha solver invoked", "captcha token reuse found"]
        result = analyze(events)
        report = format_report(result)
        assert "automated_solving" in report
        assert "token_replay" in report

    def test_report_truncation(self):
        events = [f"captcha solver variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_severity_in_report(self):
        events = ["captcha brute force"]
        result = analyze(events)
        report = format_report(result)
        assert "medium" in report


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "captcha solver"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "automated_solving", "token_replay", "ocr_attack",
            "audio_exploit", "behavioral_spoof", "rate_flooding",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_each_category_has_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
