"""Tests for botnet detection module."""

import json
import os
import tempfile

from orbit_ir.botnet import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_c2_communication(self):
        assert classify_event("detected c2 server communication") == "c2_communication"

    def test_ddos_attack(self):
        assert classify_event("massive ddos attack launched from botnet") == "ddos_attack"

    def test_bot_enrollment(self):
        assert classify_event("new bot enrollment detected on host") == "bot_enrollment"

    def test_spam_relay(self):
        assert classify_event("spam relay detected, mass mailing in progress") == "spam_relay"

    def test_credential_stuffing(self):
        assert classify_event("credential stuffing attack from distributed bots") == "credential_stuffing"

    def test_crypto_mining_botnet(self):
        assert classify_event("mining botnet activity detected on cluster") == "crypto_mining_botnet"

    def test_unknown(self):
        assert classify_event("normal user login") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "c2 beacon callback"}) == "c2_communication"

    def test_case_insensitive(self):
        assert classify_event("C2 SERVER detected") == "c2_communication"

    def test_non_string_non_dict(self):
        assert classify_event(12345) == "unknown"

    def test_syn_flood(self):
        assert classify_event("syn flood targeting port 80") == "ddos_attack"

    def test_bot_implant(self):
        assert classify_event("bot implant found in system memory") == "bot_enrollment"

    def test_combo_list(self):
        assert classify_event("combo list used in credential stuffing") == "credential_stuffing"

    def test_amplification_attack(self):
        assert classify_event("DNS amplification attack from botnet") == "ddos_attack"

    def test_smtp_abuse(self):
        assert classify_event("smtp abuse detected from compromised host") == "spam_relay"


class TestAnalyze:
    def test_empty(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"
        assert r["detection_rate"] == 0.0

    def test_single_match(self):
        r = analyze(["c2 server detected"])
        assert r["flagged_count"] == 1
        assert r["severity"] == "medium"

    def test_no_matches(self):
        r = analyze(["normal traffic", "regular login"])
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"

    def test_severity_high(self):
        events = [f"ddos attack wave {i}" for i in range(6)]
        r = analyze(events)
        assert r["severity"] == "high"

    def test_severity_critical(self):
        events = [f"c2 beacon {i}" for i in range(11)]
        r = analyze(events)
        assert r["severity"] == "critical"

    def test_category_counts(self):
        events = ["c2 server ping", "ddos attack started", "c2 beacon response"]
        r = analyze(events)
        assert r["category_counts"]["c2_communication"] == 2
        assert r["category_counts"]["ddos_attack"] == 1

    def test_detection_rate(self):
        events = ["c2 server", "normal traffic", "ddos attack", "regular"]
        r = analyze(events)
        assert r["detection_rate"] == 0.5

    def test_flagged_structure(self):
        r = analyze(["bot enrollment detected"])
        entry = r["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "bot_enrollment"
        assert entry["event"] == "bot enrollment detected"


class TestFormatReport:
    def test_format_empty(self):
        r = analyze([])
        text = format_report(r)
        assert "Botnet Detection Report" in text
        assert "0" in text

    def test_format_with_findings(self):
        r = analyze(["c2 server contact", "ddos attack launched"])
        text = format_report(r)
        assert "Botnet Detection Report" in text
        assert "c2_communication" in text
        assert "ddos_attack" in text

    def test_format_truncation(self):
        events = [f"c2 beacon signal {i}" for i in range(15)]
        r = analyze(events)
        text = format_report(r)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        r = analyze(["c2 server", "normal"])
        text = format_report(r)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["event1", "event2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a", "b"]
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "c2 server"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [{"action": "c2 server"}]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) >= 5, f"{cat} has fewer than 5 patterns"

    def test_category_names(self):
        expected = {"c2_communication", "ddos_attack", "bot_enrollment",
                    "spam_relay", "credential_stuffing", "crypto_mining_botnet"}
        assert set(CATEGORIES.keys()) == expected
