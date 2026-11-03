"""Tests for template injection detection module."""

import json
import os
import tempfile
import pytest
from orbit_ir.template_inject import (
    CATEGORIES, classify_event, analyze, format_report, load_events,
)


class TestClassifyEvent:
    def test_ssti_payload(self):
        assert classify_event("ssti payload detected in input") == "ssti_payload"

    def test_jinja_exploit(self):
        assert classify_event("jinja2 injection via user field") == "jinja_exploit"

    def test_moustache_abuse(self):
        assert classify_event("handlebars injection found") == "moustache_abuse"

    def test_expression_language(self):
        assert classify_event("ognl injection in parameter") == "expression_language"

    def test_freemarker_inject(self):
        assert classify_event("freemarker injection attempt") == "freemarker_inject"

    def test_velocity_inject(self):
        assert classify_event("velocity injection via template") == "velocity_inject"

    def test_unknown_event(self):
        assert classify_event("normal template render") == "unknown"

    def test_dict_event(self):
        event = {"action": "jinja2 injection", "source": "input"}
        assert classify_event(event) == "jinja_exploit"

    def test_non_string_non_dict(self):
        assert classify_event(99) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("SSTI PAYLOAD DETECTED") == "ssti_payload"

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
        events = ["normal render", "standard output"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["jinja2 injection found"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["jinja_exploit"] == 1

    def test_multiple_categories(self):
        events = [
            "ssti payload detected",
            "jinja2 injection attempt",
            "handlebars injection found",
            "ognl injection observed",
            "freemarker injection attempt",
            "velocity injection detected",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 6
        assert len(result["category_counts"]) == 6

    def test_severity_medium(self):
        events = ["velocity injection found"]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"ssti probe detected event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"ssti probe detected event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["jinja2 injection", "normal", "normal2", "normal3"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_events_structure(self):
        events = ["freemarker exec exploit"]
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
        assert "Template Injection Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["jinja2 injection", "velocity injection"]
        result = analyze(events)
        report = format_report(result)
        assert "jinja_exploit" in report
        assert "velocity_inject" in report

    def test_report_truncation(self):
        events = [f"ssti probe detected event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_report_severity(self):
        events = ["ognl injection found"]
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
