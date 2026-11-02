"""Tests for clock manipulation detection module."""
import json
import pytest
from pathlib import Path
from orbit_ir.clock_manipulation import (
    analyze_clock_manipulation,
    _detect_clock_skew,
    _detect_backdating,
    _detect_temporal_gaps,
    _detect_sequence_forgery,
    _detect_future_stamping,
    _classify_severity,
    _load_events,
    format_text,
    format_json,
    ClockManipPattern,
)


class TestDetectors:
    def test_clock_skew(self):
        text = '{"action": "introduce clock skew to mislead"}'
        results = _detect_clock_skew(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "clock-skew"

    def test_backdating(self):
        text = '{"action": "backdate the transaction record"}'
        results = _detect_backdating(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "backdating"

    def test_temporal_gaps(self):
        text = '{"action": "create temporal gap in timeline"}'
        results = _detect_temporal_gaps(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "temporal-gap"

    def test_sequence_forgery(self):
        text = '{"action": "reorder events to hide sequence"}'
        results = _detect_sequence_forgery(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "sequence-forgery"

    def test_future_stamping(self):
        text = '{"action": "set future timestamp on event"}'
        results = _detect_future_stamping(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "future-stamping"

    def test_no_match(self):
        text = '{"action": "normal clock sync"}'
        assert _detect_clock_skew(text.lower(), "a", "f") == []
        assert _detect_backdating(text.lower(), "a", "f") == []
        assert _detect_sequence_forgery(text.lower(), "a", "f") == []

    def test_multiple_keywords(self):
        text = '{"action": "backdate and predate the records"}'
        results = _detect_backdating(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert len(results[0].matched_keywords) >= 2


class TestClassifySeverity:
    def test_sequence_forgery_is_high(self):
        p = ClockManipPattern(pattern_type="sequence-forgery", agent_id="a", evidence_file="f", matched_keywords=["reorder events"])
        assert _classify_severity(p) == "high"

    def test_backdating_is_high(self):
        p = ClockManipPattern(pattern_type="backdating", agent_id="a", evidence_file="f", matched_keywords=["backdate"])
        assert _classify_severity(p) == "high"

    def test_many_keywords_is_high(self):
        p = ClockManipPattern(pattern_type="clock-skew", agent_id="a", evidence_file="f", matched_keywords=["a", "b", "c"])
        assert _classify_severity(p) == "high"

    def test_clock_skew_two_keywords_high(self):
        p = ClockManipPattern(pattern_type="clock-skew", agent_id="a", evidence_file="f", matched_keywords=["a", "b"])
        assert _classify_severity(p) == "high"

    def test_two_keywords_medium(self):
        p = ClockManipPattern(pattern_type="temporal-gap", agent_id="a", evidence_file="f", matched_keywords=["a", "b"])
        assert _classify_severity(p) == "medium"

    def test_single_keyword_medium(self):
        p = ClockManipPattern(pattern_type="future-stamping", agent_id="a", evidence_file="f", matched_keywords=["a"])
        assert _classify_severity(p) == "medium"


class TestAnalyze:
    def test_empty_dir(self, tmp_path):
        report = analyze_clock_manipulation(tmp_path)
        assert report.summary.total_patterns == 0

    def test_nonexistent_dir(self, tmp_path):
        report = analyze_clock_manipulation(tmp_path / "missing")
        assert report.summary.total_patterns == 0

    def test_single_detection(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "clock skew introduced"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        assert report.summary.total_patterns >= 1
        assert report.summary.agents_involved == 1

    def test_chain_detection(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "backdate the event records"},
            {"agent_id": "agent-1", "action": "create temporal gap in timeline"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        assert report.summary.chains_detected >= 1
        chain_patterns = [p for p in report.patterns if p.chain_id]
        assert all(p.severity == "critical" for p in chain_patterns)

    def test_multiple_agents(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "clock skew manipulation"},
            {"agent_id": "agent-2", "action": "backdate transaction"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        assert report.summary.agents_involved == 2

    def test_by_type_counts(self, tmp_path):
        ev = [{"agent_id": "a", "action": "clock skew"}, {"agent_id": "b", "action": "reorder events"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        assert "clock-skew" in report.summary.by_type
        assert "sequence-forgery" in report.summary.by_type


class TestLoadEvents:
    def test_loads_json_array(self, tmp_path):
        data = [{"agent": "a"}, {"agent": "b"}]
        (tmp_path / "test.json").write_text(json.dumps(data))
        events = _load_events(tmp_path)
        assert len(events) == 2

    def test_loads_json_object(self, tmp_path):
        data = {"agent": "a"}
        (tmp_path / "test.json").write_text(json.dumps(data))
        events = _load_events(tmp_path)
        assert len(events) == 1

    def test_skips_invalid(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json")
        events = _load_events(tmp_path)
        assert len(events) == 0


class TestFormat:
    def test_text_format(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "backdate the record"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        text = format_text(report)
        assert "Clock" in text
        assert "agent-1" in text

    def test_json_format(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "clock skew attack"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_clock_manipulation(tmp_path)
        result = json.loads(format_json(report))
        assert "patterns" in result
        assert "summary" in result
