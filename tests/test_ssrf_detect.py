"""Tests for SSRF attack detection module."""

import json
import os
import tempfile
import pytest
from orbit_ir.ssrf_detect import (
    CATEGORIES, classify_event, analyze, format_report, load_events,
)


class TestClassifyEvent:
    def test_internal_network_probe(self):
        assert classify_event("internal ip scan detected") == "internal_network_probe"

    def test_cloud_metadata_access(self):
        assert classify_event("169.254.169.254 endpoint hit") == "cloud_metadata_access"

    def test_localhost_access(self):
        assert classify_event("localhost request made") == "localhost_access"

    def test_url_scheme_abuse(self):
        assert classify_event("file:// scheme used in request") == "url_scheme_abuse"

    def test_dns_rebinding(self):
        assert classify_event("dns rebinding attack observed") == "dns_rebinding"

    def test_redirect_chain(self):
        assert classify_event("redirect chain ssrf detected") == "redirect_chain"

    def test_unknown_event(self):
        assert classify_event("normal web request") == "unknown"

    def test_dict_event(self):
        event = {"action": "169.254.169.254 fetch", "agent": "agent-1"}
        assert classify_event(event) == "cloud_metadata_access"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("INTERNAL IP SCAN FOUND") == "internal_network_probe"

    def test_empty_string(self):
        assert classify_event("") == "unknown"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["regular http request", "standard api call"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["localhost request to admin"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["localhost_access"] == 1

    def test_multiple_categories(self):
        events = [
            "internal ip scan attempt",
            "169.254.169.254 endpoint access",
            "localhost request made",
            "file:// scheme exploit",
            "dns rebinding payload sent",
            "redirect chain ssrf found",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 6
        assert len(result["category_counts"]) == 6

    def test_severity_medium(self):
        events = ["dns rebinding attempt"]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"loopback connection event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"loopback connection event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["localhost request", "normal", "normal2", "normal3"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_events_structure(self):
        events = ["internal ip scan found"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "SSRF Attack Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["localhost request", "dns rebinding attack"]
        result = analyze(events)
        report = format_report(result)
        assert "localhost_access" in report
        assert "dns_rebinding" in report

    def test_report_truncation(self):
        events = [f"loopback connection event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_report_severity(self):
        events = ["file:// scheme in request"]
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
            json.dump({"events": ["e1", "e2"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "test"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) > 0, f"Category {cat} has no indicators"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
