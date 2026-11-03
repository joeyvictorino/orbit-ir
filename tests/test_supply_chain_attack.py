"""Tests for supply chain attack detection module."""

import json
import os
import tempfile
import unittest

from orbit_ir.supply_chain_attack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent(unittest.TestCase):
    def test_dependency_confusion(self):
        self.assertEqual(classify_event("dependency confusion attack detected"), "dependency_confusion")

    def test_typosquatting(self):
        self.assertEqual(classify_event("typosquatting package found in registry"), "typosquatting")

    def test_build_pipeline(self):
        self.assertEqual(classify_event("build pipeline compromise via CI injection"), "build_pipeline_compromise")

    def test_package_poisoning(self):
        self.assertEqual(classify_event("malicious package uploaded to npm"), "package_poisoning")

    def test_update_hijack(self):
        self.assertEqual(classify_event("malicious update pushed to clients"), "update_hijack")

    def test_code_signing(self):
        self.assertEqual(classify_event("stolen signing key used for binary"), "code_signing_abuse")

    def test_unknown(self):
        self.assertEqual(classify_event("regular package installation"), "unknown")

    def test_none_event(self):
        self.assertEqual(classify_event(None), "unknown")

    def test_empty_string(self):
        self.assertEqual(classify_event(""), "unknown")

    def test_whitespace_only(self):
        self.assertEqual(classify_event("   "), "unknown")

    def test_dict_event(self):
        self.assertEqual(classify_event({"alert": "dependency confusion in npm"}), "dependency_confusion")

    def test_case_insensitive(self):
        self.assertEqual(classify_event("TYPOSQUATTING package detected"), "typosquatting")

    def test_non_string_non_dict(self):
        self.assertEqual(classify_event(3.14), "unknown")

    def test_trojanized_dependency(self):
        self.assertEqual(classify_event("trojanized dependency found in requirements"), "package_poisoning")

    def test_ci_poisoning(self):
        self.assertEqual(classify_event("ci poisoning detected in workflow"), "build_pipeline_compromise")

    def test_combosquatting(self):
        self.assertEqual(classify_event("combosquatting attack on package name"), "typosquatting")

    def test_dict_multiple_values(self):
        self.assertEqual(
            classify_event({"source": "registry", "detail": "forged certificate used"}),
            "code_signing_abuse",
        )

    def test_auto_update_exploit(self):
        self.assertEqual(classify_event("auto-update exploit delivering payload"), "update_hijack")


class TestAnalyze(unittest.TestCase):
    def test_empty(self):
        result = analyze([])
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["flagged_count"], 0)
        self.assertEqual(result["severity"], "none")
        self.assertAlmostEqual(result["detection_rate"], 0.0)

    def test_single_match(self):
        result = analyze(["dependency confusion attack"])
        self.assertEqual(result["flagged_count"], 1)
        self.assertEqual(result["severity"], "medium")

    def test_no_matches(self):
        result = analyze(["npm install express", "pip install flask"])
        self.assertEqual(result["flagged_count"], 0)
        self.assertEqual(result["severity"], "none")

    def test_severity_high(self):
        events = [f"typosquatting package #{i}" for i in range(7)]
        result = analyze(events)
        self.assertEqual(result["severity"], "high")

    def test_severity_critical(self):
        events = [f"malicious package #{i}" for i in range(12)]
        result = analyze(events)
        self.assertEqual(result["severity"], "critical")

    def test_category_counts(self):
        events = ["dependency confusion", "typosquatting", "dependency confusion again"]
        result = analyze(events)
        self.assertEqual(result["category_counts"]["dependency_confusion"], 2)
        self.assertEqual(result["category_counts"]["typosquatting"], 1)

    def test_detection_rate(self):
        events = ["malicious package", "safe install", "ci poisoning", "normal"]
        result = analyze(events)
        self.assertAlmostEqual(result["detection_rate"], 0.5)

    def test_flagged_structure(self):
        result = analyze(["stolen signing key found"])
        entry = result["flagged_events"][0]
        self.assertEqual(entry["index"], 0)
        self.assertEqual(entry["category"], "code_signing_abuse")
        self.assertEqual(entry["event"], "stolen signing key found")


class TestFormatReport(unittest.TestCase):
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        self.assertIn("Supply Chain Attack Detection Report", report)
        self.assertIn("Severity:          none", report)

    def test_format_with_findings(self):
        result = analyze(["dependency confusion", "malicious package"])
        report = format_report(result)
        self.assertIn("Flagged:           2", report)
        self.assertIn("Categories:", report)

    def test_format_truncation(self):
        events = [f"malicious package #{i}" for i in range(15)]
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
            json.dump({"events": ["e1"]}, f)
            path = f.name
        try:
            events = load_events(path)
            self.assertEqual(events, ["e1"])
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"alert": "typosquatting"}, f)
            path = f.name
        try:
            events = load_events(path)
            self.assertEqual(events, [{"alert": "typosquatting"}])
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
