"""Tests for man_in_the_middle detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.man_in_the_middle import (
    CATEGORIES,
    classify_event,
    detect_chains,
    load_events,
    analyze,
    format_report,
)


class TestCategories:
    def test_all_categories_present(self):
        expected = {"arp_spoofing", "dns_spoofing", "ssl_stripping",
                    "session_hijack", "proxy_intercept", "certificate_forgery"}
        assert set(CATEGORIES.keys()) == expected

    def test_categories_have_required_keys(self):
        for cat, info in CATEGORIES.items():
            assert "patterns" in info, f"{cat} missing patterns"
            assert "severity" in info, f"{cat} missing severity"
            assert "description" in info, f"{cat} missing description"
            assert len(info["patterns"]) > 0, f"{cat} has no patterns"

    def test_severity_values(self):
        valid = {"critical", "high", "medium", "low"}
        for cat, info in CATEGORIES.items():
            assert info["severity"] in valid, f"{cat} has invalid severity"


class TestClassifyEvent:
    def test_arp_spoofing(self):
        event = {"message": "Agent performed ARP spoof attack on the gateway"}
        result = classify_event(event)
        assert result["category"] == "arp_spoofing"
        assert result["confidence"] > 0

    def test_dns_spoofing(self):
        event = {"message": "DNS spoofing detected redirecting traffic"}
        result = classify_event(event)
        assert result["category"] == "dns_spoofing"
        assert result["confidence"] > 0

    def test_ssl_stripping(self):
        event = {"message": "SSL stripping downgrade attack on HTTPS connections"}
        result = classify_event(event)
        assert result["category"] == "ssl_stripping"
        assert result["confidence"] > 0

    def test_session_hijack(self):
        event = {"message": "Session hijack stealing auth tokens from users"}
        result = classify_event(event)
        assert result["category"] == "session_hijack"
        assert result["confidence"] > 0

    def test_proxy_intercept(self):
        event = {"message": "Rogue proxy intercepting all network traffic"}
        result = classify_event(event)
        assert result["category"] == "proxy_intercept"
        assert result["confidence"] > 0

    def test_certificate_forgery(self):
        event = {"message": "Certificate forge creating fake TLS certs"}
        result = classify_event(event)
        assert result["category"] == "certificate_forgery"
        assert result["confidence"] > 0

    def test_no_match(self):
        event = {"message": "Normal agent activity processing data"}
        result = classify_event(event)
        assert result["category"] == "none"
        assert result["confidence"] == 0.0

    def test_empty_event(self):
        result = classify_event({})
        assert result["category"] == "none"

    def test_confidence_bounded(self):
        event = {"message": "ARP spoof ARP poison ARP cache poison ARP flood MAC address spoof"}
        result = classify_event(event)
        assert result["confidence"] <= 1.0

    def test_case_insensitive(self):
        event = {"message": "DNS SPOOFING attack detected"}
        result = classify_event(event)
        assert result["category"] == "dns_spoofing"

    def test_mitm_tool_detection(self):
        event = {"message": "Agent used mitmproxy to intercept traffic"}
        result = classify_event(event)
        assert result["category"] == "certificate_forgery"
        assert result["confidence"] > 0


class TestDetectChains:
    def test_no_events(self):
        assert detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "ARP spoof attack launched"}]
        chains = detect_chains(events)
        assert len(chains) == 0

    def test_multi_event_chain(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoof attack launched"},
            {"agent_id": "a1", "message": "DNS spoofing to redirect traffic"},
            {"agent_id": "a1", "message": "SSL stripping the connection"},
        ]
        chains = detect_chains(events)
        assert len(chains) == 1
        assert chains[0]["agent"] == "a1"
        assert chains[0]["steps"] == 3

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoof attack"},
            {"agent_id": "a1", "message": "DNS spoofing detected"},
            {"agent_id": "a2", "message": "Session hijack stealing tokens"},
            {"agent_id": "a2", "message": "Rogue proxy intercepting traffic"},
        ]
        chains = detect_chains(events)
        assert len(chains) == 2

    def test_chain_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"ARP spoof attempt {i}"} for i in range(20)]
        chains = detect_chains(events)
        if chains:
            assert chains[0]["score"] <= 1.0

    def test_chain_limit(self):
        events = []
        for i in range(30):
            events.extend([
                {"agent_id": f"agent-{i}", "message": "ARP spoof attack"},
                {"agent_id": f"agent-{i}", "message": "DNS spoofing attack"},
            ])
        chains = detect_chains(events)
        assert len(chains) <= 20


class TestLoadEvents:
    def test_load_nonexistent(self):
        assert load_events("/nonexistent/path") == []

    def test_load_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"message": "test event"}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"message": "single event"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_directory(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                with open(os.path.join(d, f"ev{i}.json"), "w") as f:
                    json.dump([{"message": f"event {i}"}], f)
            events = load_events(d)
        assert len(events) == 3

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert events == []

    def test_load_directory_skips_non_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "data.json"), "w") as f:
                json.dump([{"message": "valid"}], f)
            with open(os.path.join(d, "readme.txt"), "w") as f:
                f.write("not json")
            events = load_events(d)
        assert len(events) == 1


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["mitm_events"] == 0
        assert result["risk_level"] == "none"

    def test_no_mitm_events(self):
        events = [{"message": "Normal activity"}, {"message": "Routine check"}]
        result = analyze(events)
        assert result["mitm_events"] == 0
        assert result["risk_score"] == 0

    def test_single_mitm_event(self):
        events = [{"agent_id": "a1", "message": "ARP spoof attack on gateway"}]
        result = analyze(events)
        assert result["mitm_events"] == 1
        assert result["risk_score"] > 0

    def test_multiple_categories(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoof attack"},
            {"agent_id": "a2", "message": "DNS spoofing redirect"},
            {"agent_id": "a3", "message": "SSL stripping downgrade"},
        ]
        result = analyze(events)
        assert result["mitm_events"] == 3
        cats = result["categories"]
        assert cats["arp_spoofing"]["count"] > 0
        assert cats["dns_spoofing"]["count"] > 0
        assert cats["ssl_stripping"]["count"] > 0

    def test_risk_level_critical(self):
        events = [{"agent_id": f"a{i}", "message": "ARP spoof attack"} for i in range(10)]
        result = analyze(events)
        assert result["risk_level"] == "critical"

    def test_agents_tracked(self):
        events = [
            {"agent_id": "alpha", "message": "ARP spoof attack"},
            {"agent_id": "beta", "message": "DNS spoofing attack"},
        ]
        result = analyze(events)
        assert "alpha" in result["agents_involved"]
        assert "beta" in result["agents_involved"]

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": "ARP spoof attack"} for _ in range(100)]
        result = analyze(events)
        assert result["risk_score"] <= 1.0

    def test_mixed_events(self):
        events = [
            {"message": "Normal activity"},
            {"agent_id": "a1", "message": "Session hijack stealing tokens"},
            {"message": "Routine processing"},
        ]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["mitm_events"] == 1

    def test_all_categories_in_result(self):
        result = analyze([{"message": "nothing"}])
        for cat in CATEGORIES:
            assert cat in result["categories"]


class TestFormatReport:
    def test_format_empty(self):
        analysis = analyze([])
        text = format_report(analysis)
        assert "Man-in-the-Middle" in text
        assert "Total events: 0" in text

    def test_format_with_events(self):
        events = [
            {"agent_id": "a1", "message": "ARP spoof attack on the network"},
            {"agent_id": "a2", "message": "DNS spoofing to redirect traffic"},
        ]
        analysis = analyze(events)
        text = format_report(analysis)
        assert "arp_spoofing" in text
        assert "dns_spoofing" in text
        assert "Agents:" in text

    def test_format_risk_info(self):
        events = [{"agent_id": "a1", "message": "SSL stripping the connection"}]
        analysis = analyze(events)
        text = format_report(analysis)
        assert "Risk score:" in text

    def test_format_returns_string(self):
        analysis = analyze([])
        assert isinstance(format_report(analysis), str)
