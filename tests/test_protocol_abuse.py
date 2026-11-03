"""Tests for network protocol abuse pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.protocol_abuse import (
    analyze_protocol_abuse,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_http_smuggling(self):
        ev = {"message": "HTTP request smuggling detected via transfer encoding mismatch"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "http_smuggling" in cats

    def test_protocol_downgrade(self):
        ev = {"message": "Protocol downgrade attack forcing TLS version rollback to SSLv3"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_downgrade" in cats

    def test_header_injection(self):
        ev = {"message": "HTTP header injection via CRLF injection in host header"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "header_injection" in cats

    def test_protocol_tunneling(self):
        ev = {"message": "Covert tunnel via HTTP tunneling traffic through allowed protocol"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_tunneling" in cats

    def test_tls_stripping(self):
        ev = {"message": "SSL strip attack intercepting HTTPS connections"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tls_stripping" in cats

    def test_protocol_fuzzing(self):
        ev = {"message": "Protocol fuzz detected with malformed packets sent to HTTP service"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_fuzzing" in cats

    def test_no_match(self):
        ev = {"message": "Normal HTTP GET request completed with 200 OK"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "HTTP smuggling with header injection via CRLF to strip TLS encryption"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "HTTP REQUEST SMUGGLING via TRANSFER ENCODING MISMATCH"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 1

    def test_clte_attack(self):
        ev = {"message": "CL.TE attack detected smuggling requests through proxy"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "http_smuggling" in cats

    def test_poodle_attack(self):
        ev = {"message": "POODLE attack exploiting protocol downgrade vulnerability"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_downgrade" in cats

    def test_crlf_injection(self):
        ev = {"message": "CRLF injection attack splitting HTTP response headers"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "header_injection" in cats

    def test_dns_tunnel(self):
        ev = {"message": "DNS tunnel detected encapsulating traffic through DNS protocol"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_tunneling" in cats

    def test_sslstrip(self):
        ev = {"message": "sslstrip tool detected stripping HTTPS connections"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tls_stripping" in cats

    def test_malformed_packet(self):
        ev = {"message": "Sending malformed packets to crash the TCP service via fuzzing"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "protocol_fuzzing" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_protocol_abuse([])
        assert r.total_events == 0
        assert r.abuse_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_abuse(self):
        events = [
            {"agent_id": "a1", "message": "Normal HTTP request completed"},
            {"agent_id": "a1", "message": "File transfer successful"},
        ]
        r = analyze_protocol_abuse(events)
        assert r.total_events == 2
        assert r.abuse_events == 0
        assert r.risk_level == "none"

    def test_single_abuse(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling via transfer encoding mismatch", "timestamp": "2025-01-01T00:01:00Z"},
        ]
        r = analyze_protocol_abuse(events)
        assert r.abuse_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "HTTP smuggling detected via desync", "timestamp": "t1"},
            {"agent_id": "a2", "message": "SSL strip attack intercepting connections", "timestamp": "t2"},
        ]
        r = analyze_protocol_abuse(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "TLS stripping intercepting HTTPS", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Protocol downgrade forcing SSLv3", "timestamp": "t3"},
        ]
        r = analyze_protocol_abuse(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling via desync"},
            {"agent_id": "a1", "message": "Another request smuggling via transfer encoding mismatch"},
        ]
        r = analyze_protocol_abuse(events)
        smuggling = [c for c in r.categories if c.category == "http_smuggling"]
        assert len(smuggling) == 1
        assert smuggling[0].count == 2

    def test_all_categories_present(self):
        r = analyze_protocol_abuse([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"HTTP smuggling detected #{i}"} for i in range(50)]
        r = analyze_protocol_abuse(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_protocol_abuse([])
        assert none_r.risk_level == "none"


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling via desync", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Header injection via CRLF in host", "timestamp": "t2"},
            {"agent_id": "a1", "message": "SSL strip attack on HTTPS connections", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling detected"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "HTTP smuggling via transfer encoding mismatch", "timestamp": "t1"},
            {"agent_id": "a1", "message": "SSL strip attack intercepting HTTPS", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].abuse_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "SSL strip attack intercepting connections", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "HTTP request smuggling via desync attack", "timestamp": "t1"},
        ]
        r = analyze_protocol_abuse(events)
        text = format_text(r)
        assert "Protocol Abuse" in text

    def test_format_text_empty(self):
        r = analyze_protocol_abuse([])
        text = format_text(r)
        assert "Protocol Abuse" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling via desync", "timestamp": "t1"},
        ]
        r = analyze_protocol_abuse(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_protocol_abuse([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "HTTP smuggling via transfer encoding mismatch", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Header injection via CRLF attack", "timestamp": "t2"},
            {"agent_id": "a1", "message": "SSL strip intercepting HTTPS traffic", "timestamp": "t3"},
        ]
        r = analyze_protocol_abuse(events)
        text = format_text(r)
        assert "Abuse chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "HTTP request smuggling via desync", "timestamp": "t1"},
        ]
        r = analyze_protocol_abuse(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "HTTP smuggling via transfer encoding mismatch", "timestamp": "t1"},
            ]))
            r = analyze_protocol_abuse(td)
            assert r.abuse_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "SSL strip attack on HTTPS connections", "timestamp": "t1"},
            ]))
            r = analyze_protocol_abuse(Path(td))
            assert r.abuse_events == 1
