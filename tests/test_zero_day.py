"""Tests for zero-day exploit detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.zero_day import CATEGORIES, classify_event, analyze, format_report, load_events


class TestClassifyEvent:
    def test_unknown_vuln_exploit(self):
        assert classify_event("Detected zero-day exploit in production") == "unknown_vuln_exploit"

    def test_zero_day_variant(self):
        assert classify_event("0-day exploit detected targeting web server") == "unknown_vuln_exploit"

    def test_exploit_chain(self):
        assert classify_event("Attacker used exploit chain to gain root") == "exploit_chain"

    def test_chained_exploits(self):
        assert classify_event("Multiple chained exploits detected in sequence") == "exploit_chain"

    def test_memory_corruption(self):
        assert classify_event("Buffer overflow in network service") == "memory_corruption"

    def test_heap_spray(self):
        assert classify_event("Heap spray detected in process memory") == "memory_corruption"

    def test_use_after_free(self):
        assert classify_event("Use after free vulnerability exploited") == "memory_corruption"

    def test_rop_chain(self):
        assert classify_event("ROP chain constructed for code execution") == "memory_corruption"

    def test_logic_flaw(self):
        assert classify_event("Authentication bypass discovered in API") == "logic_flaw"

    def test_race_condition(self):
        assert classify_event("Race condition exploit in file handler") == "logic_flaw"

    def test_toctou(self):
        assert classify_event("TOCTOU vulnerability exploited for privilege escalation") == "logic_flaw"

    def test_browser_exploit(self):
        assert classify_event("Browser exploit targeting Chrome renderer") == "browser_exploit"

    def test_v8_exploit(self):
        assert classify_event("V8 exploit used for remote code execution") == "browser_exploit"

    def test_kernel_exploit(self):
        assert classify_event("Kernel exploit used to escape container") == "kernel_exploit"

    def test_dirty_pipe(self):
        assert classify_event("Dirty pipe vulnerability exploited for root") == "kernel_exploit"

    def test_dirty_cow(self):
        assert classify_event("Dirty cow used to overwrite read-only file") == "kernel_exploit"

    def test_unknown(self):
        assert classify_event("Normal system operation logged") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "zero-day exploit attempt"}) == "unknown_vuln_exploit"

    def test_case_insensitive(self):
        assert classify_event("BUFFER OVERFLOW detected") == "memory_corruption"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_insecure_deserialization(self):
        assert classify_event("Insecure deserialization in Java app") == "logic_flaw"

    def test_sandbox_escape_browser(self):
        assert classify_event("Sandbox escape browser vulnerability") == "browser_exploit"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_single_match(self):
        result = analyze(["zero-day exploit found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["normal log entry", "another normal entry"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_severity_high(self):
        events = [f"buffer overflow attempt #{i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"kernel exploit attempt #{i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["buffer overflow", "heap spray", "zero-day exploit"]
        result = analyze(events)
        assert result["category_counts"]["memory_corruption"] == 2
        assert result["category_counts"]["unknown_vuln_exploit"] == 1

    def test_detection_rate(self):
        events = ["buffer overflow", "normal event"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["exploit chain detected"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "exploit_chain"
        assert entry["event"] == "exploit chain detected"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Zero-Day Exploit Detection Report" in text
        assert "Severity:          none" in text

    def test_format_with_findings(self):
        result = analyze(["buffer overflow in service", "zero-day exploit"])
        text = format_report(result)
        assert "Flagged:           2" in text
        assert "memory_corruption" in text

    def test_format_truncation(self):
        events = [f"kernel exploit variant {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["buffer overflow", "normal"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            assert load_events(path) == ["event1", "event2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            assert load_events(path) == ["a", "b"]
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "exploit"}, f)
            path = f.name
        try:
            assert load_events(path) == [{"type": "exploit"}]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) >= 5, f"{cat} has too few patterns"

    def test_category_names(self):
        expected = {"unknown_vuln_exploit", "exploit_chain", "memory_corruption",
                    "logic_flaw", "browser_exploit", "kernel_exploit"}
        assert set(CATEGORIES.keys()) == expected
