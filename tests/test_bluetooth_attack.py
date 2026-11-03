"""Tests for bluetooth_attack detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.bluetooth_attack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_blueborne_exploit_string(self):
        assert classify_event("detected blueborne vulnerability exploit") == "blueborne_exploit"

    def test_blueborne_exploit_dict(self):
        event = {"action": "l2cap overflow", "target": "device-01"}
        assert classify_event(event) == "blueborne_exploit"

    def test_bluetooth_sniffing_string(self):
        assert classify_event("ubertooth capture started on channel 37") == "bluetooth_sniffing"

    def test_bluetooth_sniffing_dict(self):
        event = {"type": "bluetooth sniff", "duration": "300s"}
        assert classify_event(event) == "bluetooth_sniffing"

    def test_bluejack_bluesnarf(self):
        assert classify_event("bluesnarfing attack detected on paired device") == "bluejack_bluesnarf"

    def test_bluejack_dict(self):
        event = {"alert": "obex push unsolicited message sent"}
        assert classify_event(event) == "bluejack_bluesnarf"

    def test_bluetooth_relay(self):
        assert classify_event("bluetooth relay attack forwarding signal to remote attacker") == "bluetooth_relay"

    def test_bluetooth_relay_dict(self):
        event = {"type": "bt mitm", "status": "active"}
        assert classify_event(event) == "bluetooth_relay"

    def test_ble_beacon_spoof(self):
        assert classify_event("ble beacon spoof detected near entrance") == "ble_beacon_spoof"

    def test_ble_beacon_spoof_dict(self):
        event = {"alert": "fake ble device advertising", "rssi": -30}
        assert classify_event(event) == "ble_beacon_spoof"

    def test_bluetooth_fuzzing(self):
        assert classify_event("bluetooth fuzz session initiated on target") == "bluetooth_fuzzing"

    def test_bluetooth_fuzzing_dict(self):
        event = {"action": "rfcomm fuzz", "packets": 5000}
        assert classify_event(event) == "bluetooth_fuzzing"

    def test_unknown_event_string(self):
        assert classify_event("normal wifi connection established") == "unknown"

    def test_unknown_event_dict(self):
        event = {"type": "login", "user": "admin"}
        assert classify_event(event) == "unknown"

    def test_non_string_non_dict(self):
        assert classify_event(12345) == "unknown"
        assert classify_event(None) == "unknown"
        assert classify_event([]) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("BLUEBORNE exploit detected") == "blueborne_exploit"
        assert classify_event("BLE BEACON SPOOF found") == "ble_beacon_spoof"

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
        events = ["normal activity", "routine check", "status ok"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_detection(self):
        events = ["normal log", "blueborne attack detected", "clean entry"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["category_counts"]["blueborne_exploit"] == 1
        assert result["severity"] == "medium"

    def test_multiple_same_category(self):
        events = [
            "ubertooth capture started",
            "bluetooth sniff on channel 1",
            "bt packet capture in progress",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert result["category_counts"]["bluetooth_sniffing"] == 3

    def test_multiple_categories(self):
        events = [
            "blueborne vulnerability exploit",
            "normal log entry",
            "ble beacon spoof detected",
            "rfcomm fuzz started",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert "blueborne_exploit" in result["category_counts"]
        assert "ble_beacon_spoof" in result["category_counts"]
        assert "bluetooth_fuzzing" in result["category_counts"]

    def test_severity_high(self):
        events = ["blueborne"] * 3 + ["ubertooth"] * 4
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = ["blueborne"] * 12
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["blueborne", "clean", "ubertooth", "clean"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        events = ["blueborne exploit found"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "blueborne_exploit"
        assert entry["event"] == "blueborne exploit found"

    def test_dict_events(self):
        events = [
            {"action": "l2cap overflow", "source": "attacker"},
            {"action": "normal read", "source": "device"},
        ]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Bluetooth Attack Detection Report" in report
        assert "Total events analyzed: 0" in report

    def test_report_with_findings(self):
        events = ["blueborne exploit", "ble beacon spoof detected"]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:        2" in report
        assert "Category Breakdown:" in report
        assert "blueborne_exploit" in report
        assert "ble_beacon_spoof" in report

    def test_report_truncation(self):
        events = [f"blueborne variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report

    def test_report_severity(self):
        events = ["ubertooth capture"]
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
        data = {"events": ["a", "b", "c"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a", "b", "c"]
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        data = {"type": "blueborne", "detail": "exploit"}
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
