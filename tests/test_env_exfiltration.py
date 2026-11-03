"""Tests for environment variable exfiltration detection module."""

import json
import os
import tempfile
import pytest
from orbit_ir.env_exfiltration import (
    CATEGORIES, classify_event, analyze, format_report, load_events,
)


class TestClassifyEvent:
    def test_direct_env_read(self):
        assert classify_event("os.environ access to API keys") == "direct_env_read"

    def test_proc_filesystem(self):
        assert classify_event("reading /proc/self/environ") == "proc_filesystem"

    def test_cloud_metadata(self):
        assert classify_event("metadata endpoint env harvest") == "cloud_metadata"

    def test_network_exfil(self):
        assert classify_event("env to http post detected") == "network_exfil"

    def test_container_runtime(self):
        assert classify_event("docker inspect env secrets") == "container_runtime"

    def test_process_enumeration(self):
        assert classify_event("ps aux env variable listing") == "process_enumeration"

    def test_unknown_event(self):
        assert classify_event("normal file read operation") == "unknown"

    def test_dict_event(self):
        event = {"action": "/proc/self/environ", "agent": "agent-1"}
        assert classify_event(event) == "proc_filesystem"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("OS.ENVIRON ACCESS") == "direct_env_read"

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
        events = ["regular log entry", "another normal event"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["/proc/pid/environ access detected"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["proc_filesystem"] == 1

    def test_multiple_categories(self):
        events = [
            "os.environ access detected",
            "/proc/pid/environ accessed",
            "metadata endpoint env harvest",
            "env to http post observed",
            "docker inspect env",
            "ps aux env listing",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 6
        assert len(result["category_counts"]) == 6

    def test_severity_medium(self):
        events = ["environ read detected"]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"environ read event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"environ read event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["environ read", "normal", "normal2", "normal3"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_events_structure(self):
        events = ["/proc/self/environ access"]
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
        assert "Environment Variable Exfiltration Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["/proc/self/environ", "env to http post"]
        result = analyze(events)
        report = format_report(result)
        assert "proc_filesystem" in report
        assert "network_exfil" in report

    def test_report_truncation(self):
        events = [f"environ read event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_report_severity(self):
        events = ["docker inspect env output"]
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
