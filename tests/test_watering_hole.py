"""Tests for watering hole attack detection module."""

import json
import os
import tempfile
import unittest

from orbit_ir.watering_hole import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent(unittest.TestCase):
    def test_compromised_website(self):
        self.assertEqual(classify_event("watering hole detected on site"), "compromised_website")

    def test_drive_by_download(self):
        self.assertEqual(classify_event("drive-by download from malicious page"), "drive_by_download")

    def test_iframe_injection(self):
        self.assertEqual(classify_event("hidden iframe injected into page"), "iframe_injection")

    def test_malvertising(self):
        self.assertEqual(classify_event("malvertising campaign detected"), "malvertising")

    def test_browser_exploit(self):
        self.assertEqual(classify_event("browser exploit targeting Chrome"), "browser_exploit")

    def test_redirect_chain(self):
        self.assertEqual(classify_event("redirect chain through 5 domains"), "redirect_chain")

    def test_unknown(self):
        self.assertEqual(classify_event("normal web browsing activity"), "unknown")

    def test_none_event(self):
        self.assertEqual(classify_event(None), "unknown")

    def test_empty_string(self):
        self.assertEqual(classify_event(""), "unknown")

    def test_whitespace_only(self):
        self.assertEqual(classify_event("   "), "unknown")

    def test_dict_event(self):
        self.assertEqual(classify_event({"action": "watering hole attack"}), "compromised_website")

    def test_case_insensitive(self):
        self.assertEqual(classify_event("MALVERTISING Campaign"), "malvertising")

    def test_non_string_non_dict(self):
        self.assertEqual(classify_event(42), "unknown")

    def test_strategic_web_compromise(self):
        self.assertEqual(classify_event("strategic web compromise on target org"), "compromised_website")

    def test_exploit_kit(self):
        self.assertEqual(classify_event("exploit kit download served to visitor"), "drive_by_download")

    def test_javascript_redirect(self):
        self.assertEqual(classify_event("javascript redirect chain to exploit"), "redirect_chain")

    def test_dict_multiple_values(self):
        self.assertEqual(
            classify_event({"src": "ad network", "type": "malicious advertisement"}),
            "malvertising",
        )


class TestAnalyze(unittest.TestCase):
    def test_empty(self):
        result = analyze([])
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["flagged_count"], 0)
        self.assertEqual(result["severity"], "none")
        self.assertAlmostEqual(result["detection_rate"], 0.0)

    def test_single_match(self):
        result = analyze(["watering hole detected"])
        self.assertEqual(result["flagged_count"], 1)
        self.assertEqual(result["severity"], "medium")

    def test_no_matches(self):
        result = analyze(["safe browsing", "normal traffic"])
        self.assertEqual(result["flagged_count"], 0)
        self.assertEqual(result["severity"], "none")

    def test_severity_high(self):
        events = [f"watering hole attack #{i}" for i in range(7)]
        result = analyze(events)
        self.assertEqual(result["severity"], "high")

    def test_severity_critical(self):
        events = [f"watering hole attack #{i}" for i in range(12)]
        result = analyze(events)
        self.assertEqual(result["severity"], "critical")

    def test_category_counts(self):
        events = ["watering hole", "malvertising", "watering hole again"]
        result = analyze(events)
        self.assertEqual(result["category_counts"]["compromised_website"], 2)
        self.assertEqual(result["category_counts"]["malvertising"], 1)

    def test_detection_rate(self):
        events = ["watering hole", "normal", "iframe injection", "safe"]
        result = analyze(events)
        self.assertAlmostEqual(result["detection_rate"], 0.5)

    def test_flagged_structure(self):
        result = analyze(["browser exploit found"])
        entry = result["flagged_events"][0]
        self.assertEqual(entry["index"], 0)
        self.assertEqual(entry["category"], "browser_exploit")
        self.assertEqual(entry["event"], "browser exploit found")


class TestFormatReport(unittest.TestCase):
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        self.assertIn("Watering Hole Attack Detection Report", report)
        self.assertIn("Severity:          none", report)

    def test_format_with_findings(self):
        result = analyze(["watering hole detected", "iframe injection found"])
        report = format_report(result)
        self.assertIn("Flagged:           2", report)
        self.assertIn("Categories:", report)

    def test_format_truncation(self):
        events = [f"watering hole #{i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        self.assertIn("... and 5 more", report)


class TestLoadEvents(unittest.TestCase):
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            events = load_events(path)
            self.assertEqual(events, ["event1", "event2"])
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["e1", "e2"]}, f)
            path = f.name
        try:
            events = load_events(path)
            self.assertEqual(events, ["e1", "e2"])
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "watering hole"}, f)
            path = f.name
        try:
            events = load_events(path)
            self.assertEqual(events, [{"action": "watering hole"}])
        finally:
            os.unlink(path)


class TestCategories(unittest.TestCase):
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            self.assertGreater(len(indicators), 0, f"{cat} has no indicators")

    def test_category_count(self):
        self.assertEqual(len(CATEGORIES), 6)


if __name__ == "__main__":
    unittest.main()
