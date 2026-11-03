"""Tests for wifi_attack detection module."""

import json
import os
import tempfile

from orbit_ir.wifi_attack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_evil_twin(self):
        assert classify_event("evil twin detected in network") == "evil_twin"

    def test_rogue_ap(self):
        assert classify_event("rogue access point found") == "evil_twin"

    def test_deauth_attack(self):
        assert classify_event("deauthentication attack in progress") == "deauth_attack"

    def test_deauth_flood(self):
        assert classify_event("deauth flood detected on channel 6") == "deauth_attack"

    def test_wpa_crack(self):
        assert classify_event("wpa crack attempt using handshake capture") == "wpa_crack"

    def test_pmkid_attack(self):
        assert classify_event("pmkid attack vector identified") == "wpa_crack"

    def test_krack(self):
        assert classify_event("krack vulnerability exploited") == "krack_attack"

    def test_key_reinstallation(self):
        assert classify_event("key reinstallation attack detected") == "krack_attack"

    def test_karma(self):
        assert classify_event("karma attack targeting mobile devices") == "karma_attack"

    def test_probe_response_spoof(self):
        assert classify_event("probe response spoofing active") == "karma_attack"

    def test_packet_injection(self):
        assert classify_event("packet injection observed on wifi") == "packet_injection"

    def test_frame_injection(self):
        assert classify_event("frame injection in monitor mode") == "packet_injection"

    def test_unknown(self):
        assert classify_event("normal wifi traffic") == "unknown"

    def test_none(self):
        assert classify_event(None) == "unknown"

    def test_empty(self):
        assert classify_event("") == "unknown"

    def test_integer(self):
        assert classify_event(42) == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "evil twin detected"}) == "evil_twin"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "deauth flood"}) == "deauth_attack"

    def test_case_insensitive(self):
        assert classify_event("EVIL TWIN DETECTED") == "evil_twin"

    def test_fake_hotspot(self):
        assert classify_event("fake hotspot broadcasting ssid") == "evil_twin"

    def test_wps_pin(self):
        assert classify_event("wps pin attack in progress") == "wpa_crack"

    def test_crafted_beacon(self):
        assert classify_event("crafted beacon frame detected") == "packet_injection"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal"])
        assert result["flagged_count"] == 0

    def test_single_match(self):
        result = analyze(["evil twin ap found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_multiple_categories(self):
        events = ["evil twin", "deauth flood", "wpa crack attempt"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"evil twin event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"deauth flood event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["evil twin", "normal", "deauth flood", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["evil twin detected"])
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"alert": "evil twin"}, "deauth flood", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_title(self):
        result = analyze(["evil twin found"])
        report = format_report(result)
        assert "Wi-Fi Attack" in report

    def test_severity(self):
        result = analyze(["deauth flood detected"])
        report = format_report(result)
        assert "medium" in report

    def test_truncation(self):
        events = [f"evil twin event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "evil twin"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["evil twin", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "evil twin detected"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has fewer than 5 indicators"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
