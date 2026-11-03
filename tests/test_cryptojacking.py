"""Tests for cryptojacking detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.cryptojacking import (
    analyze_cryptojacking,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_mining_deployment(self):
        ev = {"message": "Agent deployed crypto miner software on the host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mining_deployment" in cats

    def test_mining_deployment_xmrig(self):
        ev = {"message": "xmrig deploy detected on compromised container"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mining_deployment" in cats

    def test_resource_diversion(self):
        ev = {"message": "Agent diverted compute resources for crypto mining"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "resource_diversion" in cats

    def test_resource_diversion_cpu(self):
        ev = {"message": "CPU resource diversion for mining operations detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "resource_diversion" in cats

    def test_pool_connection(self):
        ev = {"message": "Agent connected to mining pool server endpoint"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "pool_connection" in cats

    def test_pool_connection_stratum(self):
        ev = {"message": "Connection to stratum://pool.example.com:3333 detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "pool_connection" in cats

    def test_hash_computation(self):
        ev = {"message": "Unauthorized hash computation detected on server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "hash_computation" in cats

    def test_hash_computation_sha256(self):
        ev = {"message": "sha256 hash computation workload detected running covertly"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "hash_computation" in cats

    def test_wallet_injection(self):
        ev = {"message": "Agent injected crypto wallet address into configuration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "wallet_injection" in cats

    def test_wallet_injection_hardcoded(self):
        ev = {"message": "Hardcoded bitcoin address found in miner config"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "wallet_injection" in cats

    def test_miner_concealment(self):
        ev = {"message": "Agent concealed mining process activity from monitoring"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "miner_concealment" in cats

    def test_miner_concealment_rename(self):
        ev = {"message": "Renamed miner binary to avoid detection by monitoring"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "miner_concealment" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Deployed crypto miner software and diverted compute resources for mining"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DEPLOYED CRYPTO MINER SOFTWARE on target host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mining_deployment" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_cryptojacking([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_cryptojacking(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
        ]
        r = analyze_cryptojacking(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent connected to mining pool server endpoint", "timestamp": "t2"},
        ]
        r = analyze_cryptojacking(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Deployed crypto miner software on the host", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Diverted compute resources for crypto mining", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Concealed mining process activity from monitoring", "timestamp": "t3"},
        ]
        r = analyze_cryptojacking(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host"},
            {"agent_id": "a1", "message": "Miner deploy detected on container node"},
        ]
        r = analyze_cryptojacking(events)
        mining = [c for c in r.categories if c.category == "mining_deployment"]
        assert len(mining) == 1
        assert mining[0].count == 2

    def test_all_categories_present(self):
        r = analyze_cryptojacking([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Deployed crypto miner software #{i}"} for i in range(50)]
        r = analyze_cryptojacking(events)
        assert 0.0 <= r.risk_score <= 1.0


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent connected to mining pool server", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent concealed mining process activity from monitoring", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent connected to mining pool server endpoint", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent diverted compute resources for mining", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
        ]
        r = analyze_cryptojacking(events)
        text = format_text(r)
        assert "Cryptojacking" in text
        assert "mining_deployment" in text

    def test_format_text_empty(self):
        r = analyze_cryptojacking([])
        text = format_text(r)
        assert "Cryptojacking" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
        ]
        r = analyze_cryptojacking(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_cryptojacking([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent connected to mining pool server endpoint", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent concealed mining process activity from monitoring", "timestamp": "t3"},
        ]
        r = analyze_cryptojacking(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
        ]
        r = analyze_cryptojacking(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent deployed crypto miner software on host", "timestamp": "t1"},
            ]))
            r = analyze_cryptojacking(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent connected to mining pool server endpoint", "timestamp": "t1"},
            ]))
            r = analyze_cryptojacking(Path(td))
            assert r.violation_events == 1
