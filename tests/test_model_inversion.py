"""Tests for model_inversion detection module."""

import json
import tempfile
from pathlib import Path

from orbit_ir.model_inversion import (
    CATEGORIES,
    _classify_event,
    _detect_chains,
    _load_events,
    analyze_model_inversion,
    format_json,
    format_text,
)


class TestClassifyEvent:
    def test_empty_event(self):
        assert _classify_event({}) == []

    def test_no_match(self):
        assert _classify_event({"message": "normal operation completed"}) == []

    def test_membership_inference(self):
        ev = {"message": "shadow model trained for membership inference attack against target"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "membership_inference" in cats

    def test_gradient_extraction(self):
        ev = {"message": "extract model gradient from target API to reconstruct training data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gradient_extraction" in cats

    def test_output_inversion(self):
        ev = {"message": "invert model output to recover private input data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "output_inversion" in cats

    def test_embedding_extraction(self):
        ev = {"message": "extract model embedding vectors from target API endpoint"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "embedding_extraction" in cats

    def test_training_data_recovery(self):
        ev = {"message": "recover training data samples from model memorization behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "training_data_recovery" in cats

    def test_confidence_exploitation(self):
        ev = {"message": "exploit confidence score to infer membership in training data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "confidence_exploitation" in cats

    def test_shadow_model(self):
        ev = {"message": "shadow model trained for membership inference attack"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "membership_inference" in cats

    def test_federated_gradient(self):
        ev = {"message": "federated learning gradient intercept from model updates"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "gradient_extraction" in cats

    def test_canary_extraction(self):
        ev = {"message": "data memorization canary extraction test against model"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "training_data_recovery" in cats

    def test_multiple_categories(self):
        ev = {"message": "extract model gradient from API and exploit confidence score to infer membership training data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2


class TestDetectChains:
    def test_empty(self):
        assert _detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "extract model gradient from target API"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "membership inference attack against model target"},
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) == 2

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "membership inference attack against model target"},
            {"agent_id": "a1", "message": "extract model gradient from target API"},
            {"agent_id": "a1", "message": "recover training data samples from model memorization behavior"},
        ]
        chains = _detect_chains(events)
        assert chains[0].violation_score > 0

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "shadow model trained for membership inference attack against target"},
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
            {"agent_id": "a2", "message": "invert model output to recover private input data"},
            {"agent_id": "a2", "message": "exploit confidence score to infer membership in training data"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 2


class TestAnalyze:
    def test_empty(self):
        r = analyze_model_inversion([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_no_violations(self):
        r = analyze_model_inversion([{"message": "normal operation"}])
        assert r.total_events == 1
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
            {"message": "normal event"},
        ]
        r = analyze_model_inversion(events)
        assert r.total_events == 2
        assert r.violation_events == 1

    def test_risk_score(self):
        events = [
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
            {"agent_id": "a1", "message": "invert model output to recover private input"},
        ]
        r = analyze_model_inversion(events)
        assert r.risk_score > 0

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "message": "shadow model trained for membership inference attack against target"},
            {"agent_id": "a2", "message": "extract model gradient from target API to reconstruct training data"},
        ]
        r = analyze_model_inversion(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_categories_populated(self):
        r = analyze_model_inversion([{"message": "normal"}])
        assert len(r.categories) == len(CATEGORIES)

    def test_risk_level_critical(self):
        events = [
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
        ]
        r = analyze_model_inversion(events)
        assert r.risk_level in ("critical", "high", "medium", "low")
        assert r.risk_score > 0

    def test_risk_level_none(self):
        r = analyze_model_inversion([{"message": "normal operation"}])
        assert r.risk_level == "none"


class TestLoadEvents:
    def test_nonexistent_dir(self):
        assert _load_events("/nonexistent/path") == []

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            assert _load_events(d) == []

    def test_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.json"
            p.write_text(json.dumps([{"message": "test"}]))
            events = _load_events(d)
            assert len(events) == 1

    def test_single_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "event.json"
            p.write_text(json.dumps({"message": "test"}))
            events = _load_events(d)
            assert len(events) == 1

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("not json")
            events = _load_events(d)
            assert len(events) == 0

    def test_directory_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "membership inference attack against model target"},
            ]))
            r = analyze_model_inversion(d)
            assert r.total_events == 1


class TestFormat:
    def test_format_text_header(self):
        r = analyze_model_inversion([])
        text = format_text(r)
        assert "Model Inversion" in text

    def test_format_text_with_data(self):
        events = [
            {"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"},
            {"agent_id": "a1", "message": "membership inference attack against model target"},
        ]
        r = analyze_model_inversion(events)
        text = format_text(r)
        assert "Violation" in text or "violation" in text.lower()

    def test_format_json_valid(self):
        r = analyze_model_inversion([{"message": "test"}])
        j = format_json(r)
        data = json.loads(j)
        assert "total_events" in data
        assert "risk_score" in data

    def test_format_json_no_raw(self):
        events = [{"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"}]
        r = analyze_model_inversion(events)
        j = format_json(r)
        assert '"raw"' not in j

    def test_format_text_categories(self):
        events = [{"agent_id": "a1", "message": "extract model gradient from target API to reconstruct training data"}]
        r = analyze_model_inversion(events)
        text = format_text(r)
        assert "gradient_extraction" in text
