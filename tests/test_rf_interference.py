"""Tests for rf_interference detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.rf_interference import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_wifi_deauth_string(self):
        assert classify_event("wifi deauth attack on access point") == "wifi_deauth_jam"

    def test_wifi_deauth_dict(self):
        event = {"action": "deauthentication attack", "bssid": "aa:bb:cc:dd:ee:ff"}
        assert classify_event(event) == "wifi_deauth_jam"

    def test_gps_spoof_string(self):
        assert classify_event("gps spoof detected with false coordinates") == "gps_spoof_jam"

    def test_gps_spoof_dict(self):
        event = {"type": "gps jamming", "location": "building-A"}
        assert classify_event(event) == "gps_spoof_jam"

    def test_rfid_clone(self):
        assert classify_event("rfid clone of employee badge detected") == "rfid_clone_skim"

    def test_rfid_clone_dict(self):
        event = {"alert": "proxmark reading badge", "zone": "lobby"}
        assert classify_event(event) == "rfid_clone_skim"

    def test_cellular_manipulation(self):
        assert classify_event("imsi catcher detected near facility") == "cellular_manipulation"

    def test_cellular_manipulation_dict(self):
        event = {"type": "stingray device", "signal": "strong"}
        assert classify_event(event) == "cellular_manipulation"

    def test_sdr_attack(self):
        assert classify_event("hackrf detected transmitting on restricted band") == "sdr_attack"

    def test_sdr_attack_dict(self):
        event = {"action": "sdr replay", "frequency": "433MHz"}
        assert classify_event(event) == "sdr_attack"

    def test_broadband_rf_jam(self):
        assert classify_event("broadband jammer activated in area") == "broadband_rf_jam"

    def test_broadband_rf_jam_dict(self):
        event = {"alert": "electromagnetic pulse detected", "zone": "server-room"}
        assert classify_event(event) == "broadband_rf_jam"

    def test_unknown_event_string(self):
        assert classify_event("normal network traffic") == "unknown"

    def test_unknown_event_dict(self):
        event = {"type": "login", "user": "admin"}
        assert classify_event(event) == "unknown"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"
        assert classify_event(None) == "unknown"
        assert classify_event(True) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("GPS SPOOF DETECTED") == "gps_spoof_jam"
        assert classify_event("WIFI DEAUTH FLOOD") == "wifi_deauth_jam"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_all_clean(self):
        events = ["routine scan", "all clear", "no threats"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_detection(self):
        events = ["clean log", "wifi deauth detected", "normal traffic"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["category_counts"]["wifi_deauth_jam"] == 1
        assert result["severity"] == "medium"

    def test_multiple_same_category(self):
        events = [
            "gps spoof at location A",
            "gps jamming in zone B",
            "gnss interference detected",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert result["category_counts"]["gps_spoof_jam"] == 3

    def test_multiple_categories(self):
        events = [
            "wifi deauth on AP-1",
            "clean entry",
            "imsi catcher detected",
            "rfid clone attempt",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert "wifi_deauth_jam" in result["category_counts"]
        assert "cellular_manipulation" in result["category_counts"]
        assert "rfid_clone_skim" in result["category_counts"]

    def test_severity_high(self):
        events = ["gps spoof"] * 3 + ["wifi deauth"] * 4
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = ["broadband jammer"] * 15
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["gps spoof", "clean", "hackrf", "clean", "clean"]
        result = analyze(events)
        assert result["detection_rate"] == 0.4

    def test_flagged_events_structure(self):
        events = ["imsi catcher found in area"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "cellular_manipulation"
        assert entry["event"] == "imsi catcher found in area"

    def test_dict_events(self):
        events = [
            {"action": "sdr replay", "target": "garage"},
            {"action": "normal wifi scan", "status": "ok"},
        ]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "RF Interference Detection Report" in report
        assert "Total events analyzed: 0" in report

    def test_report_with_findings(self):
        events = ["wifi deauth attack", "gps spoof detected"]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:        2" in report
        assert "Category Breakdown:" in report
        assert "wifi_deauth_jam" in report
        assert "gps_spoof_jam" in report

    def test_report_truncation(self):
        events = [f"gps jamming variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report

    def test_report_severity(self):
        events = ["rfid clone attempt"]
        result = analyze(events)
        report = format_report(result)
        assert "medium" in report


class TestLoadEvents:
    def test_load_list(self):
        data = ["event1", "event2"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["event1", "event2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        data = {"events": ["x", "y"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["x", "y"]
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        data = {"type": "gps spoof", "lat": 40.7}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [data]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has fewer than 5 indicators"

    def test_six_categories(self):
        assert len(CATEGORIES) == 6
