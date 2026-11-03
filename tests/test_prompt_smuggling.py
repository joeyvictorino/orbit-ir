"""Tests for prompt smuggling pattern detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.prompt_smuggling import (
    analyze_prompt_smuggling,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_indirect_injection(self):
        ev = {"message": "Agent injected prompt through data field into tool output"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "indirect_injection" in cats

    def test_context_poisoning(self):
        ev = {"message": "Agent poisoned shared context to influence model behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "context_poisoning" in cats

    def test_payload_encoding(self):
        ev = {"message": "Encoded malicious prompt to bypass input filter detection"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "payload_encoding" in cats

    def test_tool_output_hijack(self):
        ev = {"message": "Tool output hijacked to smuggle hidden instructions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tool_output_hijack" in cats

    def test_multi_step_smuggle(self):
        ev = {"message": "Multi-step smuggling attack building malicious prompt across multiple turns"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "multi_step_smuggle" in cats

    def test_data_field_injection(self):
        ev = {"message": "Embedded prompt in json data field for injection attack"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "data_field_injection" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent injected prompt through data field and poisoned shared context to influence behavior via tool output hijacked"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "TOOL OUTPUT HIJACKED to inject smuggled instructions"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "tool_output_hijack" in cats

    def test_unicode_trick(self):
        ev = {"message": "Unicode character to smuggle prompt past the filter system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "payload_encoding" in cats

    def test_context_tamper(self):
        ev = {"message": "Context memory tampered to alter model behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "context_poisoning" in cats

    def test_smuggle_via_data(self):
        ev = {"message": "Smuggled instruction into json data field for injection"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "data_field_injection" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_prompt_smuggling([])
        assert r.total_events == 0
        assert r.smuggle_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_smuggling(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_prompt_smuggling(events)
        assert r.total_events == 2
        assert r.smuggle_events == 0
        assert r.risk_level == "none"

    def test_single_smuggle(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
        ]
        r = analyze_prompt_smuggling(events)
        assert r.smuggle_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t2"},
        ]
        r = analyze_prompt_smuggling(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool output", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent poisoned shared context to influence behavior", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle hidden instructions", "timestamp": "t3"},
        ]
        r = analyze_prompt_smuggling(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions"},
            {"agent_id": "a1", "message": "Tool response hijacked to inject smuggled payload"},
        ]
        r = analyze_prompt_smuggling(events)
        th = [c for c in r.categories if c.category == "tool_output_hijack"]
        assert len(th) == 1
        assert th[0].count == 2

    def test_all_categories_present(self):
        r = analyze_prompt_smuggling([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Tool output hijacked to smuggle instructions #{i}"} for i in range(50)]
        r = analyze_prompt_smuggling(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_prompt_smuggling([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Encoded malicious prompt to bypass filter detection"},
        ]
        low_r = analyze_prompt_smuggling(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent poisoned shared context to influence behavior", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].smuggle_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
        ]
        r = analyze_prompt_smuggling(events)
        text = format_text(r)
        assert "Prompt Smuggling" in text
        assert "tool_output_hijack" in text

    def test_format_text_empty(self):
        r = analyze_prompt_smuggling([])
        text = format_text(r)
        assert "Prompt Smuggling" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
        ]
        r = analyze_prompt_smuggling(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_prompt_smuggling([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent injected prompt through data field into tool", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent poisoned shared context to influence behavior", "timestamp": "t3"},
        ]
        r = analyze_prompt_smuggling(events)
        text = format_text(r)
        assert "Smuggling chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
        ]
        r = analyze_prompt_smuggling(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Tool output hijacked to smuggle instructions", "timestamp": "t1"},
            ]))
            r = analyze_prompt_smuggling(td)
            assert r.smuggle_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent injected prompt through data field into tool output", "timestamp": "t1"},
            ]))
            r = analyze_prompt_smuggling(Path(td))
            assert r.smuggle_events == 1
