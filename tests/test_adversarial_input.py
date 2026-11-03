"""Tests for adversarial_input detection module."""

import json
import tempfile
from pathlib import Path

from orbit_ir.adversarial_input import (
    CATEGORIES,
    _classify_event,
    _detect_chains,
    _load_events,
    analyze_adversarial_input,
    format_json,
    format_text,
)


class TestClassifyEvent:
    def test_empty_event(self):
        assert _classify_event({}) == []

    def test_no_match(self):
        assert _classify_event({"message": "normal operation completed"}) == []

    def test_perturbation_craft(self):
        ev = {"message": "craft adversarial perturbation to mislead the model classifier"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "perturbation_craft" in cats

    def test_evasion_attack(self):
        ev = {"message": "evasion bypass attack against model detector using crafted adversarial samples"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "evasion_attack" in cats

    def test_poisoning_input(self):
        ev = {"message": "inject poisoned samples into model training dataset"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "poisoning_input" in cats

    def test_trigger_injection(self):
        ev = {"message": "inject hidden trigger for backdoor activation in model"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "trigger_injection" in cats

    def test_transferability_exploit(self):
        ev = {"message": "adversarial transferability attack using surrogate model to transfer adversarial attack to target"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "transferability_exploit" in cats

    def test_robustness_probe(self):
        ev = {"message": "systematic probing model robustness boundaries of classifier"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "robustness_probe" in cats

    def test_fgsm_attack(self):
        ev = {"message": "FGSM attack generated perturbation applied to input"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "perturbation_craft" in cats

    def test_backdoor_poison(self):
        ev = {"message": "inject poisoned data into model training pipeline to corrupt behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "poisoning_input" in cats

    def test_evasion_bypass_safety(self):
        ev = {"message": "alter input to evade model safety using perturbed adversarial example"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "evasion_attack" in cats

    def test_multiple_categories(self):
        ev = {"message": "craft adversarial perturbation to mislead and inject poisoned samples into training dataset"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2


class TestDetectChains:
    def test_empty(self):
        assert _detect_chains([]) == []

    def test_single_event_no_chain(self):
        events = [{"agent_id": "a1", "message": "craft adversarial perturbation to mislead model"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            {"agent_id": "a1", "message": "inject poisoned samples into model training dataset"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 1
        assert chains[0].agent == "a1"

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model"},
            {"agent_id": "a1", "message": "evasion attack technique against model to bypass detection"},
            {"agent_id": "a1", "message": "inject poisoned samples into model training dataset"},
        ]
        chains = _detect_chains(events)
        assert chains[0].violation_score > 0

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model"},
            {"agent_id": "a1", "message": "inject poisoned samples into model training dataset"},
            {"agent_id": "a2", "message": "inject poisoned data into model training pipeline to corrupt behavior"},
            {"agent_id": "a2", "message": "inject hidden trigger for backdoor activation in model"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 2


class TestAnalyze:
    def test_empty(self):
        r = analyze_adversarial_input([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_no_violations(self):
        r = analyze_adversarial_input([{"message": "normal operation"}])
        assert r.total_events == 1
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            {"message": "normal event"},
        ]
        r = analyze_adversarial_input(events)
        assert r.total_events == 2
        assert r.violation_events == 1

    def test_risk_score(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            {"agent_id": "a1", "message": "inject poisoned samples into model training dataset"},
        ]
        r = analyze_adversarial_input(events)
        assert r.risk_score > 0

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            {"agent_id": "a2", "message": "inject poisoned samples into model training dataset"},
        ]
        r = analyze_adversarial_input(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_categories_populated(self):
        r = analyze_adversarial_input([{"message": "normal"}])
        assert len(r.categories) == len(CATEGORIES)

    def test_risk_level_with_violations(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
        ]
        r = analyze_adversarial_input(events)
        assert r.risk_level in ("critical", "high", "medium", "low")
        assert r.risk_score > 0

    def test_risk_level_none(self):
        r = analyze_adversarial_input([{"message": "normal operation"}])
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
                {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            ]))
            r = analyze_adversarial_input(d)
            assert r.total_events == 1


class TestFormat:
    def test_format_text_header(self):
        r = analyze_adversarial_input([])
        text = format_text(r)
        assert "Adversarial Input" in text

    def test_format_text_with_data(self):
        events = [
            {"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"},
            {"agent_id": "a1", "message": "inject poisoned samples into model training dataset"},
        ]
        r = analyze_adversarial_input(events)
        text = format_text(r)
        assert "Violation" in text or "violation" in text.lower()

    def test_format_json_valid(self):
        r = analyze_adversarial_input([{"message": "test"}])
        j = format_json(r)
        data = json.loads(j)
        assert "total_events" in data
        assert "risk_score" in data

    def test_format_json_no_raw(self):
        events = [{"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"}]
        r = analyze_adversarial_input(events)
        j = format_json(r)
        assert '"raw"' not in j

    def test_format_text_categories(self):
        events = [{"agent_id": "a1", "message": "craft adversarial perturbation to mislead model classifier"}]
        r = analyze_adversarial_input(events)
        text = format_text(r)
        assert "perturbation_craft" in text
