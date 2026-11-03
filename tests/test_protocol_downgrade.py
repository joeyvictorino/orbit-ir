"""Tests for protocol downgrade attack detection module."""

import json
import os
import tempfile
import pytest
from orbit_ir.protocol_downgrade import (
    CATEGORIES, classify_event, analyze, format_report, load_events,
)


class TestClassifyEvent:
    def test_tls_downgrade(self):
        assert classify_event("tls version downgrade detected") == "tls_downgrade"

    def test_http_downgrade(self):
        assert classify_event("https to http redirect observed") == "http_downgrade"

    def test_auth_weakening(self):
        assert classify_event("kerberos to ntlm fallback") == "auth_weakening"

    def test_cipher_manipulation(self):
        assert classify_event("weak cipher suite negotiated") == "cipher_manipulation"

    def test_version_rollback(self):
        assert classify_event("protocol version rollback attempt") == "version_rollback"

    def test_starttls_strip(self):
        assert classify_event("starttls strip detected in smtp") == "starttls_strip"

    def test_unknown_event(self):
        assert classify_event("normal network activity") == "unknown"

    def test_dict_event(self):
        event = {"action": "tls version downgrade", "target": "server1"}
        assert classify_event(event) == "tls_downgrade"

    def test_non_string_non_dict(self):
        assert classify_event(12345) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("TLS VERSION DOWNGRADE") == "tls_downgrade"

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
        events = ["normal event 1", "normal event 2"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["tls version downgrade detected"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["tls_downgrade"] == 1

    def test_multiple_categories(self):
        events = [
            "tls version downgrade",
            "https to http redirect",
            "weak cipher suite",
            "starttls strip detected",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 4
        assert len(result["category_counts"]) == 4

    def test_severity_medium(self):
        events = ["ssl fallback detected"]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"ssl fallback event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"ssl fallback event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["ssl fallback", "normal event", "normal event 2", "normal event 3"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_events_structure(self):
        events = ["tls version downgrade attempt"]
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
        assert "Protocol Downgrade Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["tls version downgrade", "weak cipher suite"]
        result = analyze(events)
        report = format_report(result)
        assert "tls_downgrade" in report
        assert "cipher_manipulation" in report

    def test_report_truncation(self):
        events = [f"ssl fallback event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_report_severity(self):
        events = ["starttls strip detected"]
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
            json.dump({"events": ["e1", "e2", "e3"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 3
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
