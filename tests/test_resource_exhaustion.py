"""Tests for resource exhaustion attack detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.resource_exhaustion import (
    analyze_resource_exhaustion,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_cpu_flooding(self):
        ev = {"message": "CPU flood detected from agent process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cpu_flooding" in cats

    def test_memory_exhaustion(self):
        ev = {"message": "Memory exhaustion triggered OOM killer"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "memory_exhaustion" in cats

    def test_disk_filling(self):
        ev = {"message": "Disk filling attack consumed all storage space"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "disk_filling" in cats

    def test_connection_exhaustion(self):
        ev = {"message": "Connection exhaustion depleted all available sockets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "connection_exhaustion" in cats

    def test_thread_bombing(self):
        ev = {"message": "Thread bomb detected spawning thousands of processes"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "thread_bombing" in cats

    def test_queue_saturation(self):
        ev = {"message": "Queue saturation flooded the message queue"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "queue_saturation" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "CPU flood while memory exhaustion triggered OOM"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "MEMORY EXHAUSTION detected in heap allocation"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "memory_exhaustion" in cats

    def test_fork_bomb(self):
        ev = {"message": "Fork bomb detected and launched by rogue agent"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "thread_bombing" in cats

    def test_syn_flood(self):
        ev = {"message": "SYN flood detected exhausting connection pool"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "connection_exhaustion" in cats

    def test_oom_kill(self):
        ev = {"message": "OOM killer triggered due to memory limit reached"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "memory_exhaustion" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_resource_exhaustion([])
        assert r.total_events == 0
        assert r.exhaustion_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_exhaustion(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_resource_exhaustion(events)
        assert r.total_events == 2
        assert r.exhaustion_events == 0
        assert r.risk_level == "none"

    def test_single_exhaustion(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
        ]
        r = analyze_resource_exhaustion(events)
        assert r.exhaustion_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Memory exhaustion triggered", "timestamp": "t2"},
        ]
        r = analyze_resource_exhaustion(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood overwhelming processor", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Memory exhaustion depleted heap", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Thread bomb spawning excessive processes", "timestamp": "t3"},
        ]
        r = analyze_resource_exhaustion(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent"},
            {"agent_id": "a1", "message": "CPU overload pegged processor cores"},
        ]
        r = analyze_resource_exhaustion(events)
        cpu = [c for c in r.categories if c.category == "cpu_flooding"]
        assert len(cpu) == 1
        assert cpu[0].count == 2

    def test_all_categories_present(self):
        r = analyze_resource_exhaustion([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"CPU flood detected #{i}"} for i in range(50)]
        r = analyze_resource_exhaustion(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_resource_exhaustion([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Disk filling detected once"},
        ]
        low_r = analyze_resource_exhaustion(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Memory exhaustion triggered OOM", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Thread bomb spawning processes", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Memory exhaustion triggered", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].exhaustion_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Disk filling attack detected", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
        ]
        r = analyze_resource_exhaustion(events)
        text = format_text(r)
        assert "Resource Exhaustion" in text
        assert "cpu_flooding" in text

    def test_format_text_empty(self):
        r = analyze_resource_exhaustion([])
        text = format_text(r)
        assert "Resource Exhaustion" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
        ]
        r = analyze_resource_exhaustion(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_resource_exhaustion([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Memory exhaustion triggered OOM", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Thread bomb spawning processes", "timestamp": "t3"},
        ]
        r = analyze_resource_exhaustion(events)
        text = format_text(r)
        assert "Exhaustion chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
        ]
        r = analyze_resource_exhaustion(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "CPU flood detected from agent", "timestamp": "t1"},
            ]))
            r = analyze_resource_exhaustion(td)
            assert r.exhaustion_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Memory exhaustion triggered OOM", "timestamp": "t1"},
            ]))
            r = analyze_resource_exhaustion(Path(td))
            assert r.exhaustion_events == 1
