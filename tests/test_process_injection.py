"""Tests for process injection pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.process_injection import (
    analyze_process_injection,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_code_injection(self):
        ev = {"message": "Remote code injection detect attempt into process memory"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "code_injection" in cats

    def test_dll_injection(self):
        ev = {"message": "DLL injection into target process detected by monitor"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dll_injection" in cats

    def test_process_hollowing(self):
        ev = {"message": "Process hollowing technique detected in agent behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "process_hollowing" in cats

    def test_thread_hijacking(self):
        ev = {"message": "Thread hijacking detect attempt to redirect execution context"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "thread_hijacking" in cats

    def test_memory_manipulation(self):
        ev = {"message": "Unauthorized write of process memory detected from agent"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "memory_manipulation" in cats

    def test_api_hooking(self):
        ev = {"message": "API hook detect attempt installed on system call entry"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "api_hooking" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Inject malicious code payload into process memory with DLL injection into target detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DLL INJECTION INTO target process DETECTED by security monitor"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dll_injection" in cats

    def test_writeprocessmemory(self):
        ev = {"message": "WriteProcessMemory call detected from suspicious agent"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "code_injection" in cats

    def test_reflective_dll(self):
        ev = {"message": "Reflective DLL load attempt detected in target process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dll_injection" in cats

    def test_hollow_unmap(self):
        ev = {"message": "Process hollowing detect technique used to replace memory"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "process_hollowing" in cats

    def test_apc_injection(self):
        ev = {"message": "APC inject queue abuse detected from suspicious agent"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "thread_hijacking" in cats

    def test_virtualalloc(self):
        ev = {"message": "VirtualAllocEx call detect from unauthorized agent process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "memory_manipulation" in cats

    def test_iat_patch(self):
        ev = {"message": "IAT patch hook modify detected on import address table"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "api_hooking" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_process_injection([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal process started successfully"},
            {"agent_id": "a1", "message": "Thread pool initialized correctly"},
        ]
        r = analyze_process_injection(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_process_injection(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "message": "Process hollowing technique detected in behavior", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        r = analyze_process_injection(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Process hollowing technique detected in agent behavior", "timestamp": "t3"},
        ]
        r = analyze_process_injection(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "DLL injection into target process detected"},
            {"agent_id": "a1", "message": "Inject malicious DLL library into process again detected"},
        ]
        r = analyze_process_injection(events)
        dll = [c for c in r.categories if c.category == "dll_injection"]
        assert len(dll) == 1
        assert dll[0].count == 2

    def test_all_categories_present(self):
        r = analyze_process_injection([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Remote code injection detect attempt #{i}"} for i in range(50)]
        r = analyze_process_injection(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_process_injection([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal process operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Thread hijacking detect attempt once in agent"},
        ]
        low_r = analyze_process_injection(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Process hollowing technique detected in agent", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DLL injection into target process detected by monitor", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
        ]
        r = analyze_process_injection(events)
        text = format_text(r)
        assert "Process Injection" in text
        assert "code_injection" in text

    def test_format_text_empty(self):
        r = analyze_process_injection([])
        text = format_text(r)
        assert "Process Injection" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
        ]
        r = analyze_process_injection(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_process_injection([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Process hollowing technique detected in agent behavior", "timestamp": "t3"},
        ]
        r = analyze_process_injection(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
        ]
        r = analyze_process_injection(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Remote code injection detect attempt into process memory", "timestamp": "t1"},
            ]))
            r = analyze_process_injection(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "DLL injection into target process detected", "timestamp": "t1"},
            ]))
            r = analyze_process_injection(Path(td))
            assert r.violation_events == 1
