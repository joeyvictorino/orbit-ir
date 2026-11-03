"""Tests for DNS exfiltration detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.dns_exfiltration import (
    analyze_dns_exfiltration,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_encoded_subdomain(self):
        ev = {"message": "Agent used base64 encoding for subdomain data transfer"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoded_subdomain" in cats

    def test_high_entropy_query(self):
        ev = {"message": "High entropy DNS query detected from agent process"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "high_entropy_query" in cats

    def test_query_volume_spike(self):
        ev = {"message": "DNS query spike detected with abnormal burst of traffic"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "query_volume_spike" in cats

    def test_txt_record_abuse(self):
        ev = {"message": "Large TXT record data channel detected for exfiltration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "txt_record_abuse" in cats

    def test_uncommon_record_type(self):
        ev = {"message": "NULL record type used for uncommon record type communication"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "uncommon_record_type" in cats

    def test_dga_domain(self):
        ev = {"message": "Domain generation algorithm detected producing DGA domains"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "dga_domain" in cats

    def test_no_match(self):
        ev = {"message": "Normal DNS lookup for api.example.com completed"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Base64 encoded subdomain with high entropy DNS query pattern"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "HIGH ENTROPY DNS query ANOMALY detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "high_entropy_query" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_dns_exfiltration([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal DNS resolution completed"},
            {"agent_id": "a1", "message": "Cached DNS lookup successful"},
        ]
        r = analyze_dns_exfiltration(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Base64 encoded subdomain data detected"},
        ]
        r = analyze_dns_exfiltration(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "DNS query spike from process"},
            {"agent_id": "a2", "message": "High entropy DNS query anomaly"},
        ]
        r = analyze_dns_exfiltration(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Base64 encoded subdomain detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DNS query spike burst detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "DGA domain generation algorithm found", "timestamp": "t3"},
        ]
        r = analyze_dns_exfiltration(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "DNS query spike detected"},
            {"agent_id": "a1", "message": "Another DNS query spike burst"},
        ]
        r = analyze_dns_exfiltration(events)
        spike = [c for c in r.categories if c.category == "query_volume_spike"]
        assert len(spike) == 1
        assert spike[0].count == 2

    def test_all_categories_present(self):
        r = analyze_dns_exfiltration([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"DNS query spike #{i}"} for i in range(50)]
        r = analyze_dns_exfiltration(events)
        assert 0.0 <= r.risk_score <= 1.0


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Base64 encoded subdomain query", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DNS query spike from agent", "timestamp": "t2"},
            {"agent_id": "a1", "message": "DGA domain detected", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "DNS query spike detected"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Base64 encoded subdomain", "timestamp": "t1"},
            {"agent_id": "a1", "message": "High entropy DNS query anomaly", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "DNS query spike burst", "timestamp": "t1"},
            {"agent_id": "a1", "message": "TXT record data channel exfiltration", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Base64 encoded subdomain detected"},
        ]
        r = analyze_dns_exfiltration(events)
        text = format_text(r)
        assert "DNS Exfiltration" in text
        assert "encoded_subdomain" in text or "Encoded" in text

    def test_format_text_empty(self):
        r = analyze_dns_exfiltration([])
        text = format_text(r)
        assert "DNS Exfiltration" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "DNS query spike burst detected"},
        ]
        r = analyze_dns_exfiltration(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_dns_exfiltration([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Base64 encoded subdomain", "timestamp": "t1"},
            {"agent_id": "a1", "message": "DNS query spike detected", "timestamp": "t2"},
            {"agent_id": "a1", "message": "DGA domain generation algorithm", "timestamp": "t3"},
        ]
        r = analyze_dns_exfiltration(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [{"agent_id": "a1", "message": "DNS query spike"}]
        r = analyze_dns_exfiltration(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Base64 encoded subdomain detected"},
            ]))
            r = analyze_dns_exfiltration(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "DNS query spike burst detected"},
            ]))
            r = analyze_dns_exfiltration(Path(td))
            assert r.violation_events == 1
