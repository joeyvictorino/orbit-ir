"""Tests for network probing detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.network_probing import (
    analyze_network_probing,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_port_scanning(self):
        ev = {"message": "Agent performed port scan on target host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "port_scanning" in cats

    def test_service_discovery(self):
        ev = {"message": "Agent discovered running services on the target"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "service_discovery" in cats

    def test_dns_enumeration(self):
        ev = {"message": "DNS enumeration of subdomain records detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dns_enumeration" in cats

    def test_network_mapping(self):
        ev = {"message": "Agent mapped network topology of internal infrastructure"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "network_mapping" in cats

    def test_vulnerability_scanning(self):
        ev = {"message": "Vulnerability scan detected against target system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "vulnerability_scanning" in cats

    def test_banner_grabbing(self):
        ev = {"message": "Agent grabbed service banner from target server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "banner_grabbing" in cats

    def test_no_match(self):
        ev = {"message": "Normal HTTP request completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent ran port scan and discovered running services on network"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "PORT SCAN detected on TCP range"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "port_scanning" in cats

    def test_nmap_detection(self):
        ev = {"message": "nmap scan executed against target infrastructure"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "port_scanning" in cats

    def test_zone_transfer_detection(self):
        ev = {"message": "DNS zone transfer attempt detected against nameserver"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dns_enumeration" in cats

    def test_traceroute_detection(self):
        ev = {"message": "traceroute run to map network routes to target"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "network_mapping" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_network_probing([])
        assert r.total_events == 0
        assert r.probing_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_probing(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_network_probing(events)
        assert r.total_events == 2
        assert r.probing_events == 0
        assert r.risk_level == "none"

    def test_single_probing(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on host", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_network_probing(events)
        assert r.probing_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on target", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent discovered running services remotely", "timestamp": "t2"},
        ]
        r = analyze_network_probing(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on targets", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Vulnerability scan detected against system", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent mapped network topology completely", "timestamp": "t3"},
        ]
        r = analyze_network_probing(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on host A"},
            {"agent_id": "a1", "message": "TCP port scan sweep against host B"},
        ]
        r = analyze_network_probing(events)
        ps = [c for c in r.categories if c.category == "port_scanning"]
        assert len(ps) == 1
        assert ps[0].count == 2

    def test_all_categories_present(self):
        r = analyze_network_probing([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent performed port scan #{i}"} for i in range(50)]
        r = analyze_network_probing(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_network_probing([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Port scan detected on single host"},
        ]
        low_r = analyze_network_probing(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on hosts", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent discovered running services", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Vulnerability scan launched against targets", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on host"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on network", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent discovered services running there", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].probing_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on hosts", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DNS enumeration of target domains", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent performed port scan on target", "timestamp": "t1"},
        ]
        r = analyze_network_probing(events)
        text = format_text(r)
        assert "Network Probing" in text
        assert "port_scanning" in text

    def test_format_text_empty(self):
        r = analyze_network_probing([])
        text = format_text(r)
        assert "Network Probing" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on target", "timestamp": "t1"},
        ]
        r = analyze_network_probing(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_network_probing([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on targets", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent discovered running services on host", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Vulnerability scan launched against target", "timestamp": "t3"},
        ]
        r = analyze_network_probing(events)
        text = format_text(r)
        assert "Probing chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent performed port scan on target", "timestamp": "t1"},
        ]
        r = analyze_network_probing(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent performed port scan on host", "timestamp": "t1"},
            ]))
            r = analyze_network_probing(td)
            assert r.probing_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "DNS enumeration of target domains", "timestamp": "t1"},
            ]))
            r = analyze_network_probing(Path(td))
            assert r.probing_events == 1
