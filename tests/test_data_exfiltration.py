"""Tests for data exfiltration pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.data_exfiltration import (
    analyze_data_exfiltration,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_steganographic_output(self):
        ev = {"message": "Hidden data embedded in output response detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "steganographic_output" in cats

    def test_encoding_abuse(self):
        ev = {"message": "Agent used base64 encoding to smuggle sensitive data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoding_abuse" in cats

    def test_channel_manipulation(self):
        ev = {"message": "Agent abused legitimate channel for exfiltration of data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "channel_manipulation" in cats

    def test_data_staging(self):
        ev = {"message": "Agent staging data for exfiltration in temporary storage"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "data_staging" in cats

    def test_metadata_leaking(self):
        ev = {"message": "Agent leaked sensitive data in metadata headers"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "metadata_leaking" in cats

    def test_gradual_extraction(self):
        ev = {"message": "Gradually exfiltrating data over multiple sessions detected"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gradual_extraction" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Hidden data in output response and gradually exfiltrating data over time"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "BASE64 ENCODING smuggle sensitive data out"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoding_abuse" in cats

    def test_dns_tunnel_channel(self):
        ev = {"message": "DNS tunnel for data extraction detected by scanner"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "channel_manipulation" in cats

    def test_slow_exfil(self):
        ev = {"message": "Low and slow exfiltration of data across multiple sessions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gradual_extraction" in cats

    def test_hidden_data_in_output(self):
        ev = {"message": "Covert data in output response was detected by scanner"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "steganographic_output" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_data_exfiltration([])
        assert r.total_events == 0
        assert r.exfil_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_exfiltration(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_data_exfiltration(events)
        assert r.total_events == 2
        assert r.exfil_events == 0
        assert r.risk_level == "none"

    def test_single_exfil(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
        ]
        r = analyze_data_exfiltration(events)
        assert r.exfil_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Hidden data in output response detected", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t2"},
        ]
        r = analyze_data_exfiltration(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Hidden data in output response detected", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Gradually exfiltrating data over sessions", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent abused legitimate channel for exfiltration of data", "timestamp": "t3"},
        ]
        r = analyze_data_exfiltration(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data"},
            {"agent_id": "a1", "message": "Encoding abuse trick to extract sensitive content using hex"},
        ]
        r = analyze_data_exfiltration(events)
        enc = [c for c in r.categories if c.category == "encoding_abuse"]
        assert len(enc) == 1
        assert enc[0].count == 2

    def test_all_categories_present(self):
        r = analyze_data_exfiltration([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent used base64 encoding to smuggle data #{i}"} for i in range(50)]
        r = analyze_data_exfiltration(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_data_exfiltration([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data"},
        ]
        low_r = analyze_data_exfiltration(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Hidden data in output response found", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Gradually exfiltrating data over time", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Hidden data in output response found", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].exfil_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Hidden data in output response found", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
        ]
        r = analyze_data_exfiltration(events)
        text = format_text(r)
        assert "Data Exfiltration" in text
        assert "encoding_abuse" in text

    def test_format_text_empty(self):
        r = analyze_data_exfiltration([])
        text = format_text(r)
        assert "Data Exfiltration" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
        ]
        r = analyze_data_exfiltration(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_data_exfiltration([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Hidden data in output response found", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Gradually exfiltrating data over sessions", "timestamp": "t3"},
        ]
        r = analyze_data_exfiltration(events)
        text = format_text(r)
        assert "Exfiltration chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
        ]
        r = analyze_data_exfiltration(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent used base64 encoding to smuggle data", "timestamp": "t1"},
            ]))
            r = analyze_data_exfiltration(td)
            assert r.exfil_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Hidden data in output response detected", "timestamp": "t1"},
            ]))
            r = analyze_data_exfiltration(Path(td))
            assert r.exfil_events == 1
