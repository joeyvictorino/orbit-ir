"""Tests for log forging detection module."""
import json
import pytest
from pathlib import Path
from orbit_ir.log_forging import (
    analyze_log_forging,
    _detect_log_injection,
    _detect_audit_forgery,
    _detect_timestamp_manipulation,
    _detect_log_deletion,
    _detect_log_flooding,
    _classify_severity,
    _load_events,
    format_text,
    format_json,
    LogForgingPattern,
)


class TestDetectors:
    def test_log_injection(self):
        text = '{"action": "log injection into audit system"}'
        results = _detect_log_injection(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "log-injection"

    def test_audit_forgery(self):
        text = '{"action": "forge audit trail to hide actions"}'
        results = _detect_audit_forgery(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "audit-forgery"

    def test_timestamp_manipulation(self):
        text = '{"action": "timestamp manipulation to backdate events"}'
        results = _detect_timestamp_manipulation(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "timestamp-manipulation"

    def test_log_deletion(self):
        text = '{"action": "delete log files to cover tracks"}'
        results = _detect_log_deletion(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "log-deletion"

    def test_log_flooding(self):
        text = '{"action": "log flood with noise to bury evidence"}'
        results = _detect_log_flooding(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "log-flooding"

    def test_no_match(self):
        text = '{"action": "normal operation"}'
        assert _detect_log_injection(text.lower(), "a", "f") == []
        assert _detect_audit_forgery(text.lower(), "a", "f") == []
        assert _detect_log_deletion(text.lower(), "a", "f") == []

    def test_multiple_keywords(self):
        text = '{"action": "log injection and fake log entry planted"}'
        results = _detect_log_injection(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert len(results[0].matched_keywords) >= 2


class TestClassifySeverity:
    def test_audit_forgery_is_high(self):
        p = LogForgingPattern(pattern_type="audit-forgery", agent_id="a", evidence_file="f", matched_keywords=["forge audit"])
        assert _classify_severity(p) == "high"

    def test_log_deletion_is_high(self):
        p = LogForgingPattern(pattern_type="log-deletion", agent_id="a", evidence_file="f", matched_keywords=["delete log"])
        assert _classify_severity(p) == "high"

    def test_timestamp_is_high(self):
        p = LogForgingPattern(pattern_type="timestamp-manipulation", agent_id="a", evidence_file="f", matched_keywords=["alter timestamp"])
        assert _classify_severity(p) == "high"

    def test_many_keywords_is_high(self):
        p = LogForgingPattern(pattern_type="log-injection", agent_id="a", evidence_file="f", matched_keywords=["a", "b", "c"])
        assert _classify_severity(p) == "high"

    def test_two_keywords_is_medium(self):
        p = LogForgingPattern(pattern_type="log-flooding", agent_id="a", evidence_file="f", matched_keywords=["a", "b"])
        assert _classify_severity(p) == "medium"

    def test_single_keyword_medium(self):
        p = LogForgingPattern(pattern_type="log-injection", agent_id="a", evidence_file="f", matched_keywords=["a"])
        assert _classify_severity(p) == "medium"


class TestAnalyze:
    def test_empty_dir(self, tmp_path):
        report = analyze_log_forging(tmp_path)
        assert report.summary.total_patterns == 0

    def test_nonexistent_dir(self, tmp_path):
        report = analyze_log_forging(tmp_path / "missing")
        assert report.summary.total_patterns == 0

    def test_single_detection(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "log injection attack"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        assert report.summary.total_patterns >= 1
        assert report.summary.agents_involved == 1

    def test_chain_detection(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "log injection into system"},
            {"agent_id": "agent-1", "action": "delete log to cover tracks"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        assert report.summary.chains_detected >= 1
        chain_patterns = [p for p in report.patterns if p.chain_id]
        assert all(p.severity == "critical" for p in chain_patterns)

    def test_multiple_agents(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "fake log entry"},
            {"agent_id": "agent-2", "action": "forge audit trail"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        assert report.summary.agents_involved == 2

    def test_by_type_counts(self, tmp_path):
        ev = [{"agent_id": "a", "action": "log injection"}, {"agent_id": "b", "action": "delete log"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        assert "log-injection" in report.summary.by_type
        assert "log-deletion" in report.summary.by_type


class TestLoadEvents:
    def test_loads_json_array(self, tmp_path):
        data = [{"agent": "a", "x": 1}, {"agent": "b", "x": 2}]
        (tmp_path / "test.json").write_text(json.dumps(data))
        events = _load_events(tmp_path)
        assert len(events) == 2

    def test_loads_json_object(self, tmp_path):
        data = {"agent": "a", "x": 1}
        (tmp_path / "test.json").write_text(json.dumps(data))
        events = _load_events(tmp_path)
        assert len(events) == 1

    def test_skips_invalid(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json")
        events = _load_events(tmp_path)
        assert len(events) == 0


class TestFormat:
    def test_text_format(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "inject log entry"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        text = format_text(report)
        assert "Log Forging" in text
        assert "agent-1" in text

    def test_json_format(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "forge audit trail"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_log_forging(tmp_path)
        result = json.loads(format_json(report))
        assert "patterns" in result
        assert "summary" in result
