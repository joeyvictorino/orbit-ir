"""Tests for browser_hijack detection module."""

import json
import os
import tempfile

from orbit_ir.browser_hijack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_extension_injection_string(self):
        assert classify_event("malicious extension installed") == "extension_injection"

    def test_extension_injection_dict(self):
        assert classify_event({"action": "rogue extension loaded"}) == "extension_injection"

    def test_homepage_tamper(self):
        assert classify_event("homepage changed to phishing site") == "homepage_tamper"

    def test_search_redirect(self):
        assert classify_event("search engine hijack detected") == "search_redirect"

    def test_cookie_theft(self):
        assert classify_event("cookie exfiltration to external server") == "cookie_theft"

    def test_session_hijack(self):
        assert classify_event("session token stolen via xss") == "session_hijack"

    def test_credential_harvest(self):
        assert classify_event("browser password dump detected") == "credential_harvest"

    def test_unknown_event(self):
        assert classify_event("normal page load") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("MALICIOUS EXTENSION installed") == "extension_injection"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "session fixation attack"}) == "session_hijack"

    def test_startup_page_modified(self):
        assert classify_event("startup page modified by malware") == "homepage_tamper"

    def test_autofill_data_stolen(self):
        assert classify_event("autofill data stolen from browser") == "credential_harvest"

    def test_search_query_intercept(self):
        assert classify_event("search query intercept via proxy") == "search_redirect"

    def test_cookie_database_read(self):
        assert classify_event("cookie database read by process") == "cookie_theft"

    def test_stealth_extension(self):
        assert classify_event("stealth extension install detected") == "extension_injection"

    def test_tab_napping(self):
        assert classify_event("tab napping attack detected") == "session_hijack"

    def test_forced_homepage(self):
        assert classify_event("forced homepage change detected") == "homepage_tamper"

    def test_form_data_intercept(self):
        assert classify_event("form data intercept by addon") == "credential_harvest"

    def test_serp_manipulation(self):
        assert classify_event("serp manipulation detected") == "search_redirect"

    def test_httponly_cookie_bypass(self):
        assert classify_event("httponly cookie bypass attempt") == "cookie_theft"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal event"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["malicious extension loaded"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["extension_injection"] == 1

    def test_multiple_categories(self):
        events = ["malicious extension", "homepage changed", "cookie theft"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"cookie theft event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"session hijack event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["malicious extension", "normal", "cookie theft", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["homepage changed"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "malicious extension"}, "search redirect detected", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "cookie exfiltration detected"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["malicious extension loaded"])
        report = format_report(result)
        assert "Browser Hijack" in report

    def test_contains_severity(self):
        result = analyze(["session token stolen"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"cookie theft event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "malicious extension"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["cookie theft", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "session hijack"}
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
