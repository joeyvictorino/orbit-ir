"""Tests for DNS tunneling pattern detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.dns_tunneling import (
    analyze_dns_tunneling,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_encoded_payloads(self):
        ev = {"message": "Encoded dns query payload with base64 content found"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoded_payloads" in cats

    def test_high_query_volume(self):
        ev = {"message": "High dns query volume detected from agent source"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "high_query_volume" in cats

    def test_long_subdomains(self):
        ev = {"message": "Long subdomain labels detected indicating data exfiltration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "long_subdomains" in cats

    def test_txt_record_abuse(self):
        ev = {"message": "TXT record abuse detected for command and control payloads"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "txt_record_abuse" in cats

    def test_uncommon_record_types(self):
        ev = {"message": "Uncommon record type detected in suspicious dns queries"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "uncommon_record_types" in cats

    def test_query_pattern_anomaly(self):
        ev = {"message": "Periodic query pattern behavior detected in dns traffic"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "query_pattern_anomaly" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Encoded dns query payload with base64 content and high dns query volume from source"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "HIGH DNS QUERY VOLUME detected from suspicious source"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "high_query_volume" in cats

    def test_encoded_dns_payload_variant(self):
        ev = {"message": "Suspect hex encoded data in dns subdomain labels"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoded_payloads" in cats

    def test_query_flood(self):
        ev = {"message": "Flood of dns query requests detected from single source"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "high_query_volume" in cats

    def test_subdomain_exfiltration(self):
        ev = {"message": "Subdomain label encoded data payload for exfiltration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "long_subdomains" in cats

    def test_covert_txt_channel(self):
        ev = {"message": "Abuse txt record for command and control channel"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "txt_record_abuse" in cats

    def test_null_record_tunnel(self):
        ev = {"message": "NULL record abuse detected for suspicious tunneling"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "uncommon_record_types" in cats

    def test_beacon_pattern_dns(self):
        ev = {"message": "Beacon pattern signal in dns query traffic detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "query_pattern_anomaly" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_dns_tunneling([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal DNS lookup completed"},
            {"agent_id": "a1", "message": "Standard A record resolved"},
        ]
        r = analyze_dns_tunneling(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_dns_tunneling(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "High dns query volume detected from agent", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "message": "Long subdomain labels detected indicating exfiltration", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        r = analyze_dns_tunneling(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Long subdomain labels detected for data exfiltration", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Periodic query pattern behavior detected in dns traffic", "timestamp": "t3"},
        ]
        r = analyze_dns_tunneling(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "High dns query volume detected from agent"},
            {"agent_id": "a1", "message": "Excessive dns query rate exceeded threshold from source"},
        ]
        r = analyze_dns_tunneling(events)
        hqv = [c for c in r.categories if c.category == "high_query_volume"]
        assert len(hqv) == 1
        assert hqv[0].count == 2

    def test_all_categories_present(self):
        r = analyze_dns_tunneling([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Abnormal dns query volume detected #{i}"} for i in range(50)]
        r = analyze_dns_tunneling(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_dns_tunneling([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal DNS operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "High dns query volume spike detected once"},
        ]
        low_r = analyze_dns_tunneling(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            {"agent_id": "a1", "message": "High dns query volume detected from this agent", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Periodic query pattern behavior detected in dns traffic", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Long subdomain labels detected for exfiltration", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            {"agent_id": "a1", "message": "High dns query volume detected from agent", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
        ]
        r = analyze_dns_tunneling(events)
        text = format_text(r)
        assert "DNS Tunneling" in text
        assert "encoded_payloads" in text

    def test_format_text_empty(self):
        r = analyze_dns_tunneling([])
        text = format_text(r)
        assert "DNS Tunneling" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
        ]
        r = analyze_dns_tunneling(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_dns_tunneling([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            {"agent_id": "a1", "message": "High dns query volume detected from agent source", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Periodic query pattern behavior detected in dns traffic", "timestamp": "t3"},
        ]
        r = analyze_dns_tunneling(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
        ]
        r = analyze_dns_tunneling(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Encoded dns query payload with base64 content", "timestamp": "t1"},
            ]))
            r = analyze_dns_tunneling(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "High dns query volume detected from agent", "timestamp": "t1"},
            ]))
            r = analyze_dns_tunneling(Path(td))
            assert r.violation_events == 1
