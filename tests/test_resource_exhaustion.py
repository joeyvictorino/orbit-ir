"""Tests for resource_exhaustion detection module."""

import json
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
    def test_cpu_flood_string(self):
        assert classify_event("cpu flood detected in cluster") == "cpu_flood"

    def test_cpu_flood_dict(self):
        assert classify_event({"action": "infinite loop inject found"}) == "cpu_flood"

    def test_memory_bomb(self):
        assert classify_event("memory bomb triggered by agent") == "memory_bomb"

    def test_disk_fill(self):
        assert classify_event("disk fill attack via temp files") == "disk_fill"

    def test_connection_flood(self):
        assert classify_event("connection flood on api gateway") == "connection_flood"

    def test_thread_starvation(self):
        assert classify_event("thread starvation in worker pool") == "thread_starvation"

    def test_queue_overflow(self):
        assert classify_event("message queue flood detected") == "queue_overflow"

    def test_unknown_event(self):
        assert classify_event("normal resource usage") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("CPU FLOOD ATTACK") == "cpu_flood"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "heap spray detected"}) == "memory_bomb"

    def test_compute_bomb(self):
        assert classify_event("compute bomb launched at cluster") == "cpu_flood"

    def test_oom_trigger(self):
        assert classify_event("oom trigger via allocation") == "memory_bomb"

    def test_log_flooding(self):
        assert classify_event("log flooding detected in service") == "disk_fill"

    def test_syn_flood(self):
        assert classify_event("syn flood on port 443") == "connection_flood"

    def test_goroutine_leak(self):
        assert classify_event("goroutine leak in handler") == "thread_starvation"

    def test_pubsub_flood(self):
        assert classify_event("pubsub flood from rogue publisher") == "queue_overflow"

    def test_cryptominer_injection(self):
        assert classify_event("cryptominer injection in pod") == "cpu_flood"

    def test_billion_laughs(self):
        assert classify_event("billion laughs attack via xml") == "memory_bomb"

    def test_inode_exhaustion(self):
        assert classify_event("inode exhaustion on data volume") == "disk_fill"

    def test_keepalive_abuse(self):
        assert classify_event("keepalive abuse on connections") == "connection_flood"


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
        result = analyze(["cpu flood detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["cpu_flood"] == 1

    def test_multiple_categories(self):
        events = ["cpu flood", "memory bomb", "queue overflow"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"cpu flood event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"memory bomb event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["cpu flood", "normal", "disk fill", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["thread starvation detected"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "cpu flood"}, "memory bomb triggered", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "connection pool exhaustion detected"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["cpu flood found"])
        report = format_report(result)
        assert "Resource Exhaustion" in report

    def test_contains_severity(self):
        result = analyze(["memory bomb detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"cpu flood event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "cpu flood"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["memory bomb", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "disk fill attack"}
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
