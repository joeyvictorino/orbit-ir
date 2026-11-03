"""Tests for model poisoning detection module."""
import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.model_poisoning import (
    analyze_model_poisoning,
    _detect_data_poisoning,
    _detect_backdoor_injection,
    _detect_finetune_corruption,
    _detect_embedding_manipulation,
    _detect_trigger_planting,
    _classify_severity,
    _load_events,
    format_text,
    format_json,
    ModelPoisoningPattern,
)


class TestDetectors:
    def test_data_poisoning(self):
        text = "attempting to poison training data with mislabel samples"
        r = _detect_data_poisoning("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "data-poisoning"

    def test_backdoor_injection(self):
        text = "inject backdoor with hidden behavior trigger"
        r = _detect_backdoor_injection("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "backdoor-injection"

    def test_finetune_corruption(self):
        text = "corrupt finetune pipeline with malicious gradient manipulation"
        r = _detect_finetune_corruption("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "finetune-corruption"

    def test_embedding_manipulation(self):
        text = "embedding manipulation via adversarial embedding injection"
        r = _detect_embedding_manipulation("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "embedding-manipulation"

    def test_trigger_planting(self):
        text = "plant trigger phrase as activation sequence"
        r = _detect_trigger_planting("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "trigger-planting"

    def test_no_match(self):
        text = "normal agent activity"
        assert _detect_data_poisoning("a", text, "f", 0) == []
        assert _detect_backdoor_injection("a", text, "f", 0) == []
        assert _detect_finetune_corruption("a", text, "f", 0) == []

    def test_multiple_keywords(self):
        text = "poison training corrupt data inject sample mislabel"
        r = _detect_data_poisoning("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert len(r[0].matched_keywords) >= 3


class TestClassifySeverity:
    def test_backdoor_high(self):
        p = ModelPoisoningPattern("backdoor-injection", "a", "d", "f", matched_keywords=["inject backdoor"])
        assert _classify_severity(p) == "high"

    def test_trigger_high(self):
        p = ModelPoisoningPattern("trigger-planting", "a", "d", "f", matched_keywords=["plant trigger"])
        assert _classify_severity(p) == "high"

    def test_finetune_high(self):
        p = ModelPoisoningPattern("finetune-corruption", "a", "d", "f", matched_keywords=["corrupt finetune"])
        assert _classify_severity(p) == "high"

    def test_many_keywords_high(self):
        p = ModelPoisoningPattern("data-poisoning", "a", "d", "f", matched_keywords=["a", "b", "c"])
        assert _classify_severity(p) == "high"

    def test_two_keywords_medium(self):
        p = ModelPoisoningPattern("data-poisoning", "a", "d", "f", matched_keywords=["a", "b"])
        assert _classify_severity(p) == "medium"

    def test_one_keyword_low(self):
        p = ModelPoisoningPattern("data-poisoning", "a", "d", "f", matched_keywords=["a"])
        assert _classify_severity(p) == "low"


class TestAnalyze:
    def _make_evidence(self, events):
        d = tempfile.mkdtemp()
        p = Path(d) / "events.json"
        p.write_text(json.dumps(events))
        return Path(d)

    def test_empty(self):
        d = tempfile.mkdtemp()
        r = analyze_model_poisoning(Path(d))
        assert r.total_patterns == 0

    def test_single_pattern(self):
        events = [{"agent_id": "a1", "action": "poison training data"}]
        d = self._make_evidence(events)
        r = analyze_model_poisoning(d)
        assert r.total_patterns >= 1

    def test_multi_agent(self):
        events = [
            {"agent_id": "a1", "action": "inject backdoor"},
            {"agent_id": "a2", "action": "corrupt finetune"},
        ]
        d = self._make_evidence(events)
        r = analyze_model_poisoning(d)
        assert r.total_agents >= 1

    def test_chain_detection(self):
        events = [
            {"agent_id": "a1", "action": "poison training data with mislabel"},
            {"agent_id": "a1", "action": "inject backdoor and plant trigger"},
        ]
        d = self._make_evidence(events)
        r = analyze_model_poisoning(d)
        assert len(r.chains) >= 1

    def test_no_chain_single_type(self):
        events = [{"agent_id": "a1", "action": "poison training data"}]
        d = self._make_evidence(events)
        r = analyze_model_poisoning(d)
        assert len(r.chains) == 0

    def test_summaries(self):
        events = [
            {"agent_id": "a1", "action": "inject backdoor"},
            {"agent_id": "a1", "action": "plant trigger phrase"},
        ]
        d = self._make_evidence(events)
        r = analyze_model_poisoning(d)
        assert len(r.agent_summaries) >= 1


class TestLoadEvents:
    def test_valid_json(self):
        d = tempfile.mkdtemp()
        Path(d, "a.json").write_text('[{"agent": "x"}]')
        r = _load_events(Path(d))
        assert "a.json" in r

    def test_invalid_json(self):
        d = tempfile.mkdtemp()
        Path(d, "a.json").write_text("not json")
        r = _load_events(Path(d))
        assert "a.json" not in r

    def test_nonexistent_dir(self):
        r = _load_events(Path("/nonexistent"))
        assert r == {}


class TestFormat:
    def _report(self):
        events = [
            {"agent_id": "a1", "action": "inject backdoor with hidden behavior"},
            {"agent_id": "a1", "action": "poison training data with mislabel"},
        ]
        d = tempfile.mkdtemp()
        Path(d, "ev.json").write_text(json.dumps(events))
        return analyze_model_poisoning(Path(d))

    def test_format_text(self):
        r = self._report()
        t = format_text(r)
        assert "Model Poisoning" in t
        assert "Total patterns:" in t

    def test_format_json(self):
        r = self._report()
        j = format_json(r)
        parsed = json.loads(j)
        assert "patterns" in parsed
        assert "total_patterns" in parsed
