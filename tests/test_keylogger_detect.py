"""Tests for keylogger_detect detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.keylogger_detect import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_kernel_hooking_interrupt(self):
        assert classify_event("keyboard interrupt hook installed") == "kernel_hooking"

    def test_kernel_hooking_hid(self):
        assert classify_event({"action": "usb hid intercept detected"}) == "kernel_hooking"

    def test_kernel_hooking_filter_driver(self):
        assert classify_event("keyboard filter driver loaded") == "kernel_hooking"

    def test_api_hooking_setwindowshookex(self):
        assert classify_event("setwindowshookex wh_keyboard called") == "api_hooking"

    def test_api_hooking_getkeystate(self):
        assert classify_event({"api": "getkeystate monitor active"}) == "api_hooking"

    def test_api_hooking_rawinput(self):
        assert classify_event("rawinput hook installed by process") == "api_hooking"

    def test_form_grabbing_submit(self):
        assert classify_event("form submit intercept on login page") == "form_grabbing"

    def test_form_grabbing_password(self):
        assert classify_event({"type": "password field grab detected"}) == "form_grabbing"

    def test_form_grabbing_browser(self):
        assert classify_event("browser form steal credentials") == "form_grabbing"

    def test_clipboard_monitoring_monitor(self):
        assert classify_event("clipboard monitor active") == "clipboard_monitoring"

    def test_clipboard_monitoring_chain(self):
        assert classify_event({"action": "clipboard chain insert by unknown"}) == "clipboard_monitoring"

    def test_clipboard_monitoring_spy(self):
        assert classify_event("clipboard spy running in background") == "clipboard_monitoring"

    def test_input_device_sniff_evdev(self):
        assert classify_event("evdev sniff on keyboard device") == "input_device_sniff"

    def test_input_device_sniff_libinput(self):
        assert classify_event({"event": "libinput intercept active"}) == "input_device_sniff"

    def test_input_device_sniff_hid_raw(self):
        assert classify_event("hid raw read on input device") == "input_device_sniff"

    def test_screen_capture_keylog_screenshot(self):
        assert classify_event("screenshot on keypress triggered") == "screen_capture_keylog"

    def test_screen_capture_keylog_ocr(self):
        assert classify_event({"method": "ocr keypress capture active"}) == "screen_capture_keylog"

    def test_screen_capture_keylog_visual(self):
        assert classify_event("visual keylogger detected on session") == "screen_capture_keylog"

    def test_unknown_event(self):
        assert classify_event("normal system operation") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(12345) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("KEYBOARD INTERRUPT HOOK detected") == "kernel_hooking"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["normal log entry", "routine check", "all clear"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["normal", "keyboard interrupt hook active", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "kernel_hooking" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "keyboard interrupt hook active",
            "form submit intercept detected",
            "clipboard monitor running",
            "normal event",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"evdev sniff on device {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"clipboard monitor instance {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["keyboard interrupt hook", "normal", "form submit intercept", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["setwindowshookex wh_keyboard called"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "api_hooking"
        assert entry["event"] == "setwindowshookex wh_keyboard called"

    def test_dict_events(self):
        events = [{"action": "evdev sniff", "target": "keyboard"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Keylogger Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["keyboard interrupt hook", "form submit intercept", "clipboard monitor"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "kernel_hooking" in report

    def test_report_truncation(self):
        events = [f"clipboard monitor instance {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report


class TestLoadEvents:
    def test_load_list(self):
        data = ["event1", "event2"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == data
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
        data = {"type": "single event"}
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

    def test_category_count(self):
        assert len(CATEGORIES) == 6
