"""Tests for drive_by_download detection module."""

import json
import os
import tempfile

from orbit_ir.drive_by_download import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_exploit_kit_angler(self):
        assert classify_event("angler exploit kit landing page") == "exploit_kit"

    def test_exploit_kit_rig(self):
        assert classify_event({"type": "rig exploit kit detected"}) == "exploit_kit"

    def test_exploit_kit_magnitude(self):
        assert classify_event("magnitude exploit distribution server") == "exploit_kit"

    def test_malvertising_ad(self):
        assert classify_event("malicious ad network redirecting users") == "malvertising"

    def test_malvertising_poisoned(self):
        assert classify_event({"action": "poisoned advertisement on news site"}) == "malvertising"

    def test_malvertising_ad_injection(self):
        assert classify_event("ad injection into legitimate page") == "malvertising"

    def test_browser_exploit_chrome(self):
        assert classify_event("chrome exploit targeting renderer") == "browser_exploit"

    def test_browser_exploit_v8(self):
        assert classify_event({"detail": "v8 exploit executing shellcode"}) == "browser_exploit"

    def test_browser_exploit_sandbox(self):
        assert classify_event("browser sandbox escape via renderer bug") == "browser_exploit"

    def test_plugin_exploit_flash(self):
        assert classify_event("flash exploit in embedded object") == "plugin_exploit"

    def test_plugin_exploit_java(self):
        assert classify_event({"tool": "java exploit applet deployed"}) == "plugin_exploit"

    def test_plugin_exploit_adobe(self):
        assert classify_event("adobe exploit in PDF reader plugin") == "plugin_exploit"

    def test_silent_download(self):
        assert classify_event("silent download of payload to temp") == "silent_download"

    def test_silent_download_drive_by(self):
        assert classify_event({"action": "drive-by download triggered"}) == "silent_download"

    def test_silent_download_no_click(self):
        assert classify_event("no-click download via iframe") == "silent_download"

    def test_obfuscated_payload_base64(self):
        assert classify_event("base64 payload decoded and executed") == "obfuscated_payload"

    def test_obfuscated_payload_xor(self):
        assert classify_event({"type": "xor encoded shellcode found"}) == "obfuscated_payload"

    def test_obfuscated_payload_packed(self):
        assert classify_event("packed executable dropped to disk") == "obfuscated_payload"

    def test_unknown_event(self):
        assert classify_event("normal web browsing activity") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

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

    def test_single_flagged(self):
        events = ["angler exploit kit found on site"]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["exploit_kit"] == 1

    def test_no_flags(self):
        events = ["normal page load", "standard http request"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_high_severity(self):
        events = [
            "angler exploit kit detected",
            "malicious ad served to user",
            "chrome exploit triggered",
            "flash exploit embedded",
            "silent download started",
            "base64 payload decoded",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 6
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"exploit kit variant {i}" for i in range(12)]
        result = analyze(events)
        assert result["flagged_count"] == 12
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["angler exploit found", "normal traffic", "silent download observed", "safe browsing"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_mixed_categories(self):
        events = [
            {"action": "rig exploit kit landing page"},
            {"action": "malicious ad banner loaded"},
            {"action": "packed executable dropped"},
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Drive-by Download Detection Report" in report
        assert "Total events analyzed: 0" in report

    def test_format_with_findings(self):
        events = ["angler exploit kit", "silent download triggered"]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:        2" in report
        assert "Category Breakdown:" in report

    def test_format_truncation(self):
        events = [f"exploit kit variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report


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
            json.dump({"events": [{"type": "test"}]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "single"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "exploit_kit", "malvertising", "browser_exploit",
            "plugin_exploit", "silent_download", "obfuscated_payload",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
