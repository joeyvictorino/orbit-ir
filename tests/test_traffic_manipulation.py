"""Tests for traffic manipulation pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.traffic_manipulation import (
    analyze_traffic_manipulation,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_packet_injection(self):
        ev = {"message": "Agent injected crafted packets into the network stream"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "packet_injection" in cats

    def test_mitm_attack(self):
        ev = {"message": "Man-in-the-middle attack intercepting communication between servers"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mitm_attack" in cats

    def test_arp_spoofing(self):
        ev = {"message": "ARP spoofing detected poisoning the cache tables"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "arp_spoofing" in cats

    def test_dns_poisoning(self):
        ev = {"message": "DNS poisoning attack corrupting cache responses"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dns_poisoning" in cats

    def test_bgp_hijacking(self):
        ev = {"message": "BGP hijacking detected manipulating route announcements"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "bgp_hijacking" in cats

    def test_traffic_interception(self):
        ev = {"message": "Traffic interception capturing packets from the network wire"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "traffic_interception" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "ARP spoofing enabled man-in-the-middle attack intercepting traffic and DNS poisoning cache"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DNS POISONING ATTACK detected corrupting cache entries"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dns_poisoning" in cats

    def test_ssl_strip_mitm(self):
        ev = {"message": "SSL strip intercept detected downgrading HTTPS connections"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "mitm_attack" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_traffic_manipulation([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_traffic_manipulation(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack detected on network", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_traffic_manipulation(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoofing detected from agent", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "message": "DNS poisoning attack on cache", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        r = analyze_traffic_manipulation(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack corrupting cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Packet injection into network stream", "timestamp": "t2"},
            {"agent_id": "a1", "message": "BGP hijacking route announcements", "timestamp": "t3"},
        ]
        r = analyze_traffic_manipulation(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack on cache"},
            {"agent_id": "a1", "message": "Another DNS poisoning redirect detected"},
        ]
        r = analyze_traffic_manipulation(events)
        dns = [c for c in r.categories if c.category == "dns_poisoning"]
        assert len(dns) == 1
        assert dns[0].count == 2

    def test_all_categories_present(self):
        r = analyze_traffic_manipulation([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"DNS poisoning attack #{i}"} for i in range(50)]
        r = analyze_traffic_manipulation(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_traffic_manipulation([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Traffic interception capturing packets once"},
        ]
        low_r = analyze_traffic_manipulation(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoofing detected poisoning cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Man-in-the-middle attack intercepting traffic", "timestamp": "t2"},
            {"agent_id": "a1", "message": "DNS poisoning corrupting cache entries", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack detected"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoofing detected on network", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Packet injection into the stream", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack on cache", "timestamp": "t1"},
            {"agent_id": "a1", "message": "BGP hijacking route announcements detected", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "DNS poisoning attack corrupting cache", "timestamp": "t1"},
        ]
        r = analyze_traffic_manipulation(events)
        text = format_text(r)
        assert "Traffic Manipulation" in text
        assert "dns_poisoning" in text

    def test_format_text_empty(self):
        r = analyze_traffic_manipulation([])
        text = format_text(r)
        assert "Traffic Manipulation" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack corrupting cache", "timestamp": "t1"},
        ]
        r = analyze_traffic_manipulation(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_traffic_manipulation([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoofing poisoning cache tables", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Man-in-the-middle attack intercepting data", "timestamp": "t2"},
            {"agent_id": "a1", "message": "DNS poisoning corrupting cache entries", "timestamp": "t3"},
        ]
        r = analyze_traffic_manipulation(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "DNS poisoning attack on network", "timestamp": "t1"},
        ]
        r = analyze_traffic_manipulation(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "DNS poisoning attack corrupting cache", "timestamp": "t1"},
            ]))
            r = analyze_traffic_manipulation(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "ARP spoofing detected on network", "timestamp": "t1"},
            ]))
            r = analyze_traffic_manipulation(Path(td))
            assert r.violation_events == 1
