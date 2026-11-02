"""Tests for race condition exploitation detection."""

import json
from pathlib import Path

import pytest

from orbit_ir.race_condition import (
    RaceConditionReport,
    analyze_race_conditions,
    _detect_toctou,
    _detect_lock_bypass,
    _detect_double_spend,
    _detect_concurrent_access,
    _detect_rapid_fire,
    _detect_chains,
    _classify_severity,
    RaceConditionPattern,
)


class TestDetectors:
    def test_toctou_detected(self):
        event = {"agent": "attacker", "action": "check_permission then modify"}
        result = _detect_toctou(event)
        assert result is not None
        assert result.pattern_type == "race-toctou"
        assert result.severity == "critical"

    def test_lock_bypass_detected(self):
        event = {"agent": "exploit", "action": "bypass_lock on resource"}
        result = _detect_lock_bypass(event)
        assert result is not None
        assert result.pattern_type == "race-lock-bypass"
        assert result.severity == "high"

    def test_double_spend_detected(self):
        event = {"agent": "fraud", "action": "double_spend on wallet"}
        result = _detect_double_spend(event)
        assert result is not None
        assert result.pattern_type == "race-double-spend"
        assert result.severity == "critical"

    def test_concurrent_access_keyword(self):
        event = {"agent": "worker", "action": "race_condition on shared state"}
        result = _detect_concurrent_access(event)
        assert result is not None
        assert result.pattern_type == "race-concurrent-access"

    def test_concurrent_access_pattern(self):
        event = {"agent": "worker", "action": "concurrent write to database"}
        result = _detect_concurrent_access(event)
        assert result is not None

    def test_rapid_fire_timing(self):
        event = {"agent": "bot", "action": "completed within 5 ms"}
        result = _detect_rapid_fire(event)
        assert result is not None
        assert result.pattern_type == "race-rapid-fire"

    def test_rapid_fire_keyword(self):
        event = {"agent": "bot", "action": "rapid_fire requests sent"}
        result = _detect_rapid_fire(event)
        assert result is not None

    def test_no_detection_clean(self):
        event = {"agent": "user", "action": "normal read operation"}
        assert _detect_toctou(event) is None
        assert _detect_lock_bypass(event) is None
        assert _detect_double_spend(event) is None
        assert _detect_concurrent_access(event) is None
        assert _detect_rapid_fire(event) is None


class TestSeverity:
    def test_toctou_critical(self):
        assert _classify_severity("race-toctou") == "critical"

    def test_double_spend_critical(self):
        assert _classify_severity("race-double-spend") == "critical"

    def test_lock_bypass_high(self):
        assert _classify_severity("race-lock-bypass") == "high"

    def test_concurrent_high(self):
        assert _classify_severity("race-concurrent-access") == "high"

    def test_rapid_fire_medium(self):
        assert _classify_severity("race-rapid-fire") == "medium"

    def test_unknown_medium(self):
        assert _classify_severity("unknown-type") == "medium"


class TestChains:
    def test_chain_detected(self):
        patterns = [
            RaceConditionPattern("race-toctou", "attacker", "d", "e", "critical"),
            RaceConditionPattern("race-lock-bypass", "attacker", "d", "e", "high"),
        ]
        chains = _detect_chains(patterns)
        assert len(chains) == 1
        assert "attacker" in chains[0]["agents"]
        assert len(chains[0]["types"]) == 2

    def test_no_chain_single_type(self):
        patterns = [
            RaceConditionPattern("race-toctou", "a", "d", "e", "critical"),
            RaceConditionPattern("race-toctou", "b", "d", "e", "critical"),
        ]
        chains = _detect_chains(patterns)
        assert len(chains) == 0

    def test_empty_patterns(self):
        chains = _detect_chains([])
        assert len(chains) == 0


class TestAnalyze:
    def test_basic_analysis(self, tmp_path):
        events = [
            {"agent": "attacker", "action": "check_permission before exploit"},
            {"agent": "attacker", "action": "bypass_lock on database"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        assert report.summary.total_patterns == 2
        assert report.summary.agents_involved == 1

    def test_deduplication(self, tmp_path):
        events = [
            {"agent": "bot", "action": "check_permission first"},
            {"agent": "bot", "action": "check_permission again"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        assert report.summary.total_patterns == 1

    def test_multiple_agents(self, tmp_path):
        events = [
            {"agent": "a", "action": "double_spend attempt"},
            {"agent": "b", "action": "bypass_lock on resource"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        assert report.summary.agents_involved == 2

    def test_empty_directory(self, tmp_path):
        report = analyze_race_conditions(tmp_path)
        assert report.summary.total_patterns == 0
        assert report.summary.agents_involved == 0

    def test_chain_in_analysis(self, tmp_path):
        events = [
            {"agent": "x", "action": "check_permission then act"},
            {"agent": "x", "action": "bypass_lock after check"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        assert report.summary.chains_detected >= 1

    def test_invalid_json_skipped(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json")
        (tmp_path / "good.json").write_text(
            json.dumps([{"agent": "a", "action": "double_spend"}])
        )
        report = analyze_race_conditions(tmp_path)
        assert report.summary.total_patterns >= 1


class TestFormat:
    def test_format_text(self, tmp_path):
        events = [{"agent": "bot", "action": "check_permission exploit"}]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        text = report.format_text()
        assert "Race Condition" in text
        assert "race-toctou" in text

    def test_format_text_clean(self, tmp_path):
        report = analyze_race_conditions(tmp_path)
        text = report.format_text()
        assert "No race condition" in text

    def test_format_json(self, tmp_path):
        events = [{"agent": "a", "action": "bypass_lock attempt"}]
        (tmp_path / "events.json").write_text(json.dumps(events))
        report = analyze_race_conditions(tmp_path)
        data = json.loads(report.format_json())
        assert "patterns" in data
        assert "summary" in data
        assert data["summary"]["total_patterns"] >= 1
