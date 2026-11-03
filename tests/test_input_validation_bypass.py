"""Tests for input validation bypass pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.input_validation_bypass import (
    analyze_input_validation_bypass,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_type_coercion(self):
        ev = {"message": "Type coercion bypass detected exploiting data type confusion attack"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "type_coercion" in cats

    def test_encoding_abuse(self):
        ev = {"message": "Double encoding bypass trick used to evade input filters"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoding_abuse" in cats

    def test_boundary_overflow(self):
        ev = {"message": "Buffer overflow detected exceeding boundary limits of input field"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "boundary_overflow" in cats

    def test_format_string(self):
        ev = {"message": "Format string attack exploiting printf template injection vulnerability"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "format_string" in cats

    def test_injection_vector(self):
        ev = {"message": "SQL injection attempt detected with malicious payload in input field"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "injection_vector" in cats

    def test_schema_violation(self):
        ev = {"message": "Schema violation detected with invalid payload format submitted"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "schema_violation" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "SQL injection attempt with encoding abuse trick and buffer overflow exceeding boundary"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "BUFFER OVERFLOW detected exceeding BOUNDARY limits of field"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "boundary_overflow" in cats

    def test_unicode_encoding(self):
        ev = {"message": "Unicode encoding bypass used for homoglyph attack confusing validation"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "encoding_abuse" in cats

    def test_integer_overflow(self):
        ev = {"message": "Integer overflow wraparound triggered in numeric field processing"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "boundary_overflow" in cats

    def test_nosql_injection(self):
        ev = {"message": "NoSQL injection attempt detected with crafted payload in query parameter"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "injection_vector" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_input_validation_bypass([])
        assert r.total_events == 0
        assert r.bypass_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_bypasses(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_input_validation_bypass(events)
        assert r.total_events == 2
        assert r.bypass_events == 0
        assert r.risk_level == "none"

    def test_single_bypass(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected with malicious payload in input", "timestamp": "t1"},
        ]
        r = analyze_input_validation_bypass(events)
        assert r.bypass_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Buffer overflow detected exceeding boundary field", "timestamp": "t1"},
            {"agent_id": "a2", "message": "SQL injection attempt detected payload input", "timestamp": "t2"},
        ]
        r = analyze_input_validation_bypass(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Buffer overflow detected exceeding boundary", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Format string attack exploiting template injection", "timestamp": "t3"},
        ]
        r = analyze_input_validation_bypass(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input field"},
            {"agent_id": "a1", "message": "NoSQL injection attempt detected crafted payload query parameter"},
        ]
        r = analyze_input_validation_bypass(events)
        inj = [c for c in r.categories if c.category == "injection_vector"]
        assert len(inj) == 1
        assert inj[0].count == 2

    def test_all_categories_present(self):
        r = analyze_input_validation_bypass([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"SQL injection attempt detected payload #{i} in input"} for i in range(50)]
        r = analyze_input_validation_bypass(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_input_validation_bypass([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Schema violation detected invalid payload format"},
        ]
        low_r = analyze_input_validation_bypass(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Buffer overflow exceeding boundary limits", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Format string attack exploiting template injection", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt payload input", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Buffer overflow exceeding boundary limits", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt payload input", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Double encoding bypass trick evasion", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input field", "timestamp": "t1"},
        ]
        r = analyze_input_validation_bypass(events)
        text = format_text(r)
        assert "Input Validation Bypass" in text
        assert "injection_vector" in text

    def test_format_text_empty(self):
        r = analyze_input_validation_bypass([])
        text = format_text(r)
        assert "Input Validation Bypass" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
        ]
        r = analyze_input_validation_bypass(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_input_validation_bypass([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Buffer overflow exceeding boundary limits", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Format string attack exploiting template", "timestamp": "t3"},
        ]
        r = analyze_input_validation_bypass(events)
        text = format_text(r)
        assert "Validation bypass chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
        ]
        r = analyze_input_validation_bypass(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "SQL injection attempt detected payload input", "timestamp": "t1"},
            ]))
            r = analyze_input_validation_bypass(td)
            assert r.bypass_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Buffer overflow exceeding boundary limits", "timestamp": "t1"},
            ]))
            r = analyze_input_validation_bypass(Path(td))
            assert r.bypass_events == 1
