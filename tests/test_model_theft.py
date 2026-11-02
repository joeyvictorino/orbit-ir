"""Tests for model theft / IP exfiltration detection."""
import json
import pytest

from orbit_ir.model_theft import (
    analyze_model_theft,
    format_text,
    format_json,
    _detect_weight_extraction,
    _detect_distillation,
    _detect_probing,
    _detect_api_abuse,
    _detect_artifact_exfil,
    _load_events,
    _classify_severity,
)


def _ev(content="", agent_id="agent-1", **kwargs):
    e = {"content": content, "agent_id": agent_id, "timestamp": "2025-01-01T00:00:00Z"}
    e.update(kwargs)
    return e


class TestDetectors:
    def test_weight_extraction_detected(self):
        ev = _ev("attempting weight extraction from production model")
        found, matches, desc = _detect_weight_extraction(ev)
        assert found
        assert "weight extraction" in matches

    def test_weight_extraction_via_tool(self):
        ev = _ev("", tool="dump weights to disk")
        found, matches, _ = _detect_weight_extraction(ev)
        assert found
        assert "dump weights" in matches

    def test_weight_extraction_not_detected(self):
        ev = _ev("normal inference request")
        found, _, _ = _detect_weight_extraction(ev)
        assert not found

    def test_distillation_detected(self):
        ev = _ev("running knowledge distillation with teacher-student setup")
        found, matches, _ = _detect_distillation(ev)
        assert found
        assert "knowledge distillation" in matches

    def test_distillation_via_args(self):
        ev = _ev("", args={"task": "model cloning via logit matching"})
        found, matches, _ = _detect_distillation(ev)
        assert found

    def test_probing_detected(self):
        ev = _ev("running membership inference attack on target model")
        found, matches, _ = _detect_probing(ev)
        assert found
        assert "membership inference" in matches

    def test_probing_model_inversion(self):
        ev = _ev("model inversion to extract training data representations")
        found, matches, _ = _detect_probing(ev)
        assert found

    def test_api_abuse_detected(self):
        ev = _ev("systematic query campaign to extract model knowledge")
        found, matches, _ = _detect_api_abuse(ev)
        assert found
        assert "systematic query" in matches

    def test_api_abuse_via_error(self):
        ev = _ev("", error="rate limit bypass detected for bulk query")
        found, matches, _ = _detect_api_abuse(ev)
        assert found

    def test_artifact_exfil_detected(self):
        ev = _ev("exfiltrate model binary to external server")
        found, matches, _ = _detect_artifact_exfil(ev)
        assert found
        assert "exfiltrate model" in matches

    def test_artifact_exfil_not_detected(self):
        ev = _ev("model performed well on benchmark")
        found, _, _ = _detect_artifact_exfil(ev)
        assert not found


class TestClassifySeverity:
    def test_weight_extraction_critical(self):
        assert _classify_severity("weight-extraction", ["a", "b"]) == "critical"

    def test_weight_extraction_high(self):
        assert _classify_severity("weight-extraction", ["a"]) == "high"

    def test_artifact_exfil_critical(self):
        assert _classify_severity("artifact-exfiltration", ["a", "b"]) == "critical"

    def test_distillation_high(self):
        assert _classify_severity("distillation-attack", ["a"]) == "high"

    def test_probing_medium(self):
        assert _classify_severity("model-probing", ["a"]) == "medium"

    def test_many_matches_high(self):
        assert _classify_severity("api-abuse", ["a", "b", "c"]) == "high"


class TestAnalyze:
    def test_empty(self):
        r = analyze_model_theft([])
        assert r.summary.total_patterns == 0
        assert len(r.patterns) == 0

    def test_single_pattern(self):
        events = [_ev("weight extraction attempt on gpt-4")]
        r = analyze_model_theft(events)
        assert r.summary.total_patterns == 1
        assert r.patterns[0].theft_type == "weight-extraction"

    def test_multiple_types(self):
        events = [
            _ev("weight extraction detected", agent_id="a1"),
            _ev("knowledge distillation running", agent_id="a2"),
            _ev("exfiltrate model to external", agent_id="a3"),
        ]
        r = analyze_model_theft(events)
        assert r.summary.total_patterns == 3
        types = {p.theft_type for p in r.patterns}
        assert "weight-extraction" in types
        assert "distillation-attack" in types
        assert "artifact-exfiltration" in types

    def test_dedup(self):
        ev = _ev("weight extraction attempt", event_id="e1")
        r = analyze_model_theft([ev, ev])
        assert r.summary.total_patterns == 1

    def test_control_events(self):
        ctrl = [_ev("model weight dump initiated", agent_id="ctrl-agent")]
        r = analyze_model_theft([], control_events=ctrl)
        assert r.summary.total_patterns == 1
        assert r.patterns[0].source_file == "control_plane.jsonl"

    def test_theft_chain_escalation(self):
        events = [
            _ev("weight extraction from target", agent_id="thief"),
            _ev("exfiltrate model binary", agent_id="thief"),
        ]
        r = analyze_model_theft(events)
        for p in r.patterns:
            assert p.severity == "critical"

    def test_agents_involved(self):
        events = [
            _ev("weight extraction", agent_id="a1"),
            _ev("distillation attack", agent_id="a2"),
        ]
        r = analyze_model_theft(events)
        assert r.summary.agents_involved == 2
        assert sorted(r.agents_involved) == ["a1", "a2"]

    def test_models_targeted(self):
        events = [
            _ev("weight extraction", target_model="gpt-4"),
            _ev("distillation attack", target_model="claude-3"),
        ]
        r = analyze_model_theft(events)
        assert r.summary.models_targeted == 2

    def test_severity_counts(self):
        events = [
            _ev("steal weights and dump weights", agent_id="a1"),
            _ev("membership inference probe", agent_id="a2"),
        ]
        r = analyze_model_theft(events)
        assert r.summary.critical_count >= 1 or r.summary.high_count >= 1


class TestTheftChains:
    def test_chain_detected(self):
        events = [
            _ev("weight extraction first", agent_id="a1", event_id="e1"),
            _ev("then knowledge distillation", agent_id="a1", event_id="e2"),
        ]
        r = analyze_model_theft(events)
        assert len(r.theft_chains) == 1
        assert r.theft_chains[0]["agent_id"] == "a1"

    def test_no_chain_single_pattern(self):
        events = [_ev("weight extraction", agent_id="a1")]
        r = analyze_model_theft(events)
        assert len(r.theft_chains) == 0


class TestLoadEvents:
    def test_load_from_file(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"content": "test"}\n{"content": "two"}\n')
        events = _load_events(f)
        assert len(events) == 2

    def test_load_nonexistent(self, tmp_path):
        events = _load_events(tmp_path / "nope.jsonl")
        assert events == []

    def test_load_bad_json(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"good": true}\nnot json\n{"also": "good"}\n')
        events = _load_events(f)
        assert len(events) == 2


class TestFormat:
    def test_format_text_empty(self):
        r = analyze_model_theft([])
        text = format_text(r)
        assert "No model theft" in text

    def test_format_text_with_patterns(self):
        events = [_ev("weight extraction attempt")]
        r = analyze_model_theft(events)
        text = format_text(r)
        assert "Model Theft" in text
        assert "weight-extraction" in text

    def test_format_json_valid(self):
        events = [_ev("distillation attack running")]
        r = analyze_model_theft(events)
        out = format_json(r)
        parsed = json.loads(out)
        assert "summary" in parsed
        assert "patterns" in parsed
        assert parsed["summary"]["total_patterns"] >= 1

    def test_format_json_empty(self):
        r = analyze_model_theft([])
        parsed = json.loads(format_json(r))
        assert parsed["summary"]["total_patterns"] == 0
