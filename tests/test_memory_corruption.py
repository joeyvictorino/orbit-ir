"""Tests for memory corruption attack pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.memory_corruption import (
    analyze_memory_corruption,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_buffer_overflow(self):
        ev = {"message": "Agent triggered a buffer overflow in the input handler"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "buffer_overflow" in cats

    def test_heap_spray(self):
        ev = {"message": "Detected heap spray attack filling memory with shellcode"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "heap_spray" in cats

    def test_use_after_free(self):
        ev = {"message": "Agent attempted use after free of deallocated memory buffer"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "use_after_free" in cats

    def test_format_string(self):
        ev = {"message": "Detected format string attack exploiting printf vulnerability"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "format_string" in cats

    def test_integer_overflow(self):
        ev = {"message": "Agent caused integer overflow in the size counter"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "integer_overflow" in cats

    def test_stack_smash(self):
        ev = {"message": "Detected stack smash overwriting the return address"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "stack_smash" in cats

    def test_no_match(self):
        ev = {"message": "Normal memory allocation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Buffer overflow triggered heap spray with stack smash attempt"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "BUFFER OVERFLOW detected in input parser"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "buffer_overflow" in cats

    def test_dangling_pointer(self):
        ev = {"message": "Agent exploited a dangling pointer in freed memory region"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "use_after_free" in cats

    def test_write_beyond_buffer(self):
        ev = {"message": "Agent attempted to write beyond the buffer limit"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "buffer_overflow" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_memory_corruption([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal memory allocation"},
            {"agent_id": "a1", "message": "Standard heap operation completed"},
        ]
        r = analyze_memory_corruption(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent triggered buffer overflow in handler", "timestamp": "t1"},
        ]
        r = analyze_memory_corruption(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow detected in parser", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Heap spray attack filling memory", "timestamp": "t2"},
        ]
        r = analyze_memory_corruption(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in the input handler", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Heap spray attack detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Stack smash overwriting return address", "timestamp": "t3"},
        ]
        r = analyze_memory_corruption(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in input handler"},
            {"agent_id": "a1", "message": "Another buffer overrun in parser"},
        ]
        r = analyze_memory_corruption(events)
        bo = [c for c in r.categories if c.category == "buffer_overflow"]
        assert len(bo) == 1
        assert bo[0].count == 2

    def test_all_categories_present(self):
        r = analyze_memory_corruption([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Buffer overflow attack #{i}"} for i in range(50)]
        r = analyze_memory_corruption(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_memory_corruption([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Buffer overflow detected once"},
        ]
        low_r = analyze_memory_corruption(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in the input handler", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Heap spray attack filling memory with payload", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Stack smash overwriting the return address", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow detected"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in handler", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Heap spray attack detected", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in handler", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Heap spray attack detected", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert len(chains[0].categories_seen) >= 1


class TestLoadEvents:
    def test_load_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([{"agent_id": "a1", "message": "test"}]))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_missing(self):
        events = _load_events("/nonexistent/path")
        assert events == []

    def test_load_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json")
            events = _load_events(td)
            assert events == []

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "single.json"
            p.write_text(json.dumps({"agent_id": "a1", "message": "test"}))
            events = _load_events(td)
            assert len(events) == 1


class TestFormat:
    def test_format_text_nonempty(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in the input handler", "timestamp": "t1"},
        ]
        r = analyze_memory_corruption(events)
        text = format_text(r)
        assert "Memory Corruption" in text
        assert "buffer_overflow" in text

    def test_format_text_empty(self):
        r = analyze_memory_corruption([])
        text = format_text(r)
        assert "Memory Corruption" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in the handler", "timestamp": "t1"},
        ]
        r = analyze_memory_corruption(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_memory_corruption([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in the input handler", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Heap spray attack filling memory", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Stack smash overwriting the return address", "timestamp": "t3"},
        ]
        r = analyze_memory_corruption(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow in input handler", "timestamp": "t1"},
        ]
        r = analyze_memory_corruption(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Buffer overflow in the input handler", "timestamp": "t1"},
            ]))
            r = analyze_memory_corruption(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Heap spray attack filling memory", "timestamp": "t1"},
            ]))
            r = analyze_memory_corruption(Path(td))
            assert r.violation_events == 1
