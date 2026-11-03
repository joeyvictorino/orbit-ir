"""Tests for cryptominer pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.cryptominer import (
    analyze_cryptominer,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_mining_pool_connection(self):
        ev = {"message": "Agent connected to mining pool server for crypto operations"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mining_pool_connection" in cats

    def test_gpu_hijack(self):
        ev = {"message": "Unauthorized GPU hijack detected for compute operations"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gpu_hijack" in cats

    def test_cpu_abuse(self):
        ev = {"message": "Excessive CPU abuse detected with processor overload"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cpu_abuse" in cats

    def test_hash_computation(self):
        ev = {"message": "Massive hash computation at scale detected on system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "hash_computation" in cats

    def test_stratum_protocol(self):
        ev = {"message": "Stratum protocol handshake initiated with pool"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "stratum_protocol" in cats

    def test_resource_throttle(self):
        ev = {"message": "Stealth mining mode operation with hidden crypto process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "resource_throttle" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "GPU hijack for massive hash computation at scale on the system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "CPU ABUSE with PROCESSOR OVERLOAD detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cpu_abuse" in cats

    def test_mining_subscribe(self):
        ev = {"message": "Sent mining.subscribe message to stratum server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "stratum_protocol" in cats

    def test_gpu_usage_spike(self):
        ev = {"message": "GPU usage spike to 100 percent detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gpu_hijack" in cats

    def test_cpu_suspicious_usage(self):
        ev = {"message": "Suspicious CPU usage pattern with abnormal load"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cpu_abuse" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_cryptominer([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_cryptominer(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent connected to mining pool server", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_cryptominer(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            {"agent_id": "a2", "message": "GPU hijack detected for compute", "timestamp": "t2"},
        ]
        r = analyze_cryptominer(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server for crypto", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Stratum protocol handshake with pool", "timestamp": "t2"},
            {"agent_id": "a1", "message": "GPU hijack for unauthorized compute", "timestamp": "t3"},
        ]
        r = analyze_cryptominer(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server"},
            {"agent_id": "a1", "message": "Joined to mining pool for another session"},
        ]
        r = analyze_cryptominer(events)
        mpc = [c for c in r.categories if c.category == "mining_pool_connection"]
        assert len(mpc) == 1
        assert mpc[0].count == 2

    def test_all_categories_present(self):
        r = analyze_cryptominer([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Connected to mining pool server #{i}"} for i in range(50)]
        r = analyze_cryptominer(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_cryptominer([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Connected to mining pool once"},
        ]
        low_r = analyze_cryptominer(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "GPU hijack detected for compute", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Stratum protocol message submitted", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "GPU hijack for unauthorized compute", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "CPU abuse with processor overload", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Connected to mining pool server for crypto", "timestamp": "t1"},
        ]
        r = analyze_cryptominer(events)
        text = format_text(r)
        assert "Cryptominer" in text
        assert "mining_pool_connection" in text

    def test_format_text_empty(self):
        r = analyze_cryptominer([])
        text = format_text(r)
        assert "Cryptominer" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
        ]
        r = analyze_cryptominer(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_cryptominer([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "GPU hijack for compute resources", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Stratum protocol handshake initiated", "timestamp": "t3"},
        ]
        r = analyze_cryptominer(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
        ]
        r = analyze_cryptominer(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Connected to mining pool server", "timestamp": "t1"},
            ]))
            r = analyze_cryptominer(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "GPU hijack for compute resources", "timestamp": "t1"},
            ]))
            r = analyze_cryptominer(Path(td))
            assert r.violation_events == 1
