"""Tests for memory_scraping detection module."""

import json
import os
import tempfile

from orbit_ir.memory_scraping import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_ram_scraping(self):
        assert classify_event("ram scraping attack detected") == "ram_scraping"

    def test_memory_dump(self):
        assert classify_event("memory dump attack in progress") == "ram_scraping"

    def test_credential_dump(self):
        assert classify_event("credential dump from process memory") == "credential_dump"

    def test_lsass_dump(self):
        assert classify_event("lsass dump detected on endpoint") == "credential_dump"

    def test_mimikatz(self):
        assert classify_event("mimikatz execution detected") == "credential_dump"

    def test_heap_spray(self):
        assert classify_event("heap spray attack vector found") == "heap_spray"

    def test_use_after_free(self):
        assert classify_event("use after free exploit attempt") == "heap_spray"

    def test_cold_boot(self):
        assert classify_event("cold boot attack on server") == "cold_boot"

    def test_dram_remanence(self):
        assert classify_event("dram remanence exploitation") == "cold_boot"

    def test_spectre(self):
        assert classify_event("spectre vulnerability exploitation") == "side_channel_mem"

    def test_meltdown(self):
        assert classify_event("meltdown attack detected") == "side_channel_mem"

    def test_rowhammer(self):
        assert classify_event("rowhammer bit flip detected") == "side_channel_mem"

    def test_process_hollowing(self):
        assert classify_event("process hollowing detected in system") == "process_hollowing"

    def test_process_doppelganging(self):
        assert classify_event("process doppelganging technique used") == "process_hollowing"

    def test_unknown(self):
        assert classify_event("normal memory operation") == "unknown"

    def test_none(self):
        assert classify_event(None) == "unknown"

    def test_empty(self):
        assert classify_event("") == "unknown"

    def test_integer(self):
        assert classify_event(42) == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "mimikatz detected"}) == "credential_dump"

    def test_case_insensitive(self):
        assert classify_event("RAM SCRAPING ATTACK") == "ram_scraping"

    def test_kerberoast(self):
        assert classify_event("kerberoast attack in progress") == "credential_dump"

    def test_cache_timing(self):
        assert classify_event("cache timing attack detected") == "side_channel_mem"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal"])
        assert result["flagged_count"] == 0

    def test_single_match(self):
        result = analyze(["mimikatz execution found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_multiple_categories(self):
        events = ["ram scraping", "mimikatz", "heap spray", "spectre"]
        result = analyze(events)
        assert result["flagged_count"] == 4
        assert len(result["category_counts"]) == 4

    def test_high_severity(self):
        events = [f"ram scraping event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"mimikatz event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["ram scraping", "normal", "mimikatz", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["credential dump detected"])
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry

    def test_mixed_types(self):
        events = [{"alert": "mimikatz"}, "heap spray active", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_title(self):
        result = analyze(["ram scraping found"])
        report = format_report(result)
        assert "Memory Scraping" in report

    def test_severity(self):
        result = analyze(["mimikatz detected"])
        report = format_report(result)
        assert "medium" in report

    def test_truncation(self):
        events = [f"ram scraping event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "mimikatz"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["ram scraping", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "cold boot attack"}
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
