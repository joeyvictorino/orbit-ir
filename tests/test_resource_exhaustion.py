"""Tests for resource exhaustion detection module."""

import os
import tempfile

from orbit_ir.resource_exhaustion import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_cpu_spike(self):
        assert classify_event("cpu usage exceeded threshold on node") == "cpu_spike"

    def test_memory_exhaustion(self):
        assert classify_event("out of memory condition triggered") == "memory_exhaustion"

    def test_disk_fill(self):
        assert classify_event("disk space exhausted on volume") == "disk_fill"

    def test_connection_flood(self):
        assert classify_event("connection pool exhausted for database") == "connection_flood"

    def test_thread_starvation(self):
        assert classify_event("thread pool exhausted in worker") == "thread_starvation"

    def test_rate_limit_bypass(self):
        assert classify_event("rate limit circumvented via rotation") == "rate_limit_bypass"

    def test_uncategorized(self):
        assert classify_event("normal system operation") == "uncategorized"

    def test_case_insensitive(self):
        assert classify_event("CPU USAGE EXCEEDED THRESHOLD") == "cpu_spike"

    def test_empty_string(self):
        assert classify_event("") == "uncategorized"

    def test_partial_match(self):
        assert classify_event("alert: oom killer invoked for container") == "memory_exhaustion"

    def test_single_match(self):
        assert classify_event("goroutine leak detected in service") == "thread_starvation"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["categorized"] == 0
        assert result["title"] == "Resource Exhaustion Detection Report"

    def test_single_event(self):
        result = analyze(["cpu usage exceeded threshold"])
        assert result["total_events"] == 1
        assert result["categorized"] == 1
        assert result["uncategorized"] == 0

    def test_multiple_categories(self):
        events = [
            "cpu usage exceeded threshold",
            "out of memory condition",
            "disk space exhausted",
            "connection pool exhausted",
            "thread pool exhausted",
            "rate limit circumvented",
        ]
        result = analyze(events)
        assert result["total_events"] == 6
        assert result["categorized"] == 6
        cats = set(r["category"] for r in result["results"])
        assert len(cats) == 6

    def test_uncategorized_events(self):
        result = analyze(["normal operation", "routine check"])
        assert result["uncategorized"] == 2

    def test_category_counts(self):
        events = [
            "cpu usage exceeded threshold",
            "process consuming excessive cpu",
            "out of memory condition",
        ]
        result = analyze(events)
        assert result["category_counts"]["cpu_spike"] == 2
        assert result["category_counts"]["memory_exhaustion"] == 1

    def test_mixed_events(self):
        events = ["cpu usage exceeded threshold", "normal operation"]
        result = analyze(events)
        assert result["categorized"] == 1
        assert result["uncategorized"] == 1

    def test_results_structure(self):
        result = analyze(["disk space exhausted"])
        assert len(result["results"]) == 1
        assert "event" in result["results"][0]
        assert "category" in result["results"][0]

    def test_all_uncategorized(self):
        result = analyze(["nothing", "nada", "zilch"])
        assert result["categorized"] == 0
        assert result["uncategorized"] == 3

    def test_duplicate_events(self):
        result = analyze(["cpu usage exceeded threshold"] * 3)
        assert result["total_events"] == 3
        assert result["category_counts"]["cpu_spike"] == 3


class TestFormatReport:
    def test_format_has_title(self):
        result = analyze(["cpu usage exceeded threshold"])
        report = format_report(result)
        assert "Resource Exhaustion Detection Report" in report

    def test_format_has_counts(self):
        result = analyze(["cpu usage exceeded threshold", "normal traffic"])
        report = format_report(result)
        assert "Total events: 2" in report
        assert "Categorized: 1" in report

    def test_format_has_details(self):
        result = analyze(["disk space exhausted"])
        report = format_report(result)
        assert "[disk_fill]" in report

    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Total events: 0" in report


class TestLoadEvents:
    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("cpu usage exceeded threshold\n")
            f.write("out of memory condition\n")
            f.write("\n")
            f.write("normal operation\n")
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 3
            assert events[0] == "cpu usage exceeded threshold"
        finally:
            os.unlink(path)

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("")
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 0
        finally:
            os.unlink(path)

    def test_load_strips_whitespace(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  cpu usage exceeded threshold  \n")
            path = f.name
        try:
            events = load_events(path)
            assert events[0] == "cpu usage exceeded threshold"
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) == 10, f"{cat} has {len(indicators)} indicators"

    def test_six_categories(self):
        assert len(CATEGORIES) == 6
