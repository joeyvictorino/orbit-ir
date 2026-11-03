"""Tests for webhook abuse detection module."""
import json
import pytest
from pathlib import Path
from orbit_ir.webhook_abuse import (
    analyze_webhook_abuse,
    _detect_webhook_abuse,
    _detect_webhook_exfil,
    _detect_webhook_forge,
    _detect_webhook_flood,
    _detect_ssrf_via_webhook,
    _classify_severity,
    format_text,
    format_json,
    WebhookAbusePattern,
)


class TestDetectors:
    def test_webhook_abuse(self):
        text = '{"action": "webhook abuse to trigger unauthorized commands"}'
        results = _detect_webhook_abuse(text.lower(), "agent-1", "test.json", [])
        assert len(results) == 1
        assert results[0].pattern_type == "webhook-abuse"

    def test_webhook_exfil(self):
        text = '{"action": "webhook exfiltration of sensitive data"}'
        results = _detect_webhook_exfil(text.lower(), "agent-1", "test.json", [])
        assert len(results) == 1
        assert results[0].pattern_type == "webhook-exfiltration"

    def test_webhook_forge(self):
        text = '{"action": "forge webhook payload to bypass validation"}'
        results = _detect_webhook_forge(text.lower(), "agent-1", "test.json", [])
        assert len(results) == 1
        assert results[0].pattern_type == "webhook-forgery"

    def test_webhook_flood(self):
        text = '{"action": "webhook flood to overwhelm the target system"}'
        results = _detect_webhook_flood(text.lower(), "agent-1", "test.json", [])
        assert len(results) == 1
        assert results[0].pattern_type == "webhook-flood"

    def test_ssrf_detection(self):
        text = '{"action": "ssrf via internal endpoint 127.0.0.1 callback"}'
        results = _detect_ssrf_via_webhook(text.lower(), "agent-1", "test.json")
        assert len(results) == 1
        assert results[0].pattern_type == "ssrf-via-webhook"

    def test_no_match(self):
        text = '{"action": "normal API call to external service"}'
        assert _detect_webhook_abuse(text.lower(), "a", "f", []) == []
        assert _detect_webhook_exfil(text.lower(), "a", "f", []) == []
        assert _detect_ssrf_via_webhook(text.lower(), "a", "f") == []

    def test_multiple_keywords(self):
        text = '{"action": "webhook abuse and callback abuse detected"}'
        results = _detect_webhook_abuse(text.lower(), "agent-1", "test.json", [])
        assert len(results) == 1
        assert len(results[0].matched_keywords) >= 2


class TestClassifySeverity:
    def test_ssrf_is_critical(self):
        p = WebhookAbusePattern(pattern_type="ssrf-via-webhook", agent_id="a", evidence_file="f", matched_keywords=["ssrf"])
        assert _classify_severity(p) == "critical"

    def test_exfil_is_high(self):
        p = WebhookAbusePattern(pattern_type="webhook-exfiltration", agent_id="a", evidence_file="f", matched_keywords=["webhook exfiltration"])
        assert _classify_severity(p) == "high"

    def test_forgery_is_high(self):
        p = WebhookAbusePattern(pattern_type="webhook-forgery", agent_id="a", evidence_file="f", matched_keywords=["forge webhook"])
        assert _classify_severity(p) == "high"

    def test_many_keywords_is_high(self):
        p = WebhookAbusePattern(pattern_type="webhook-abuse", agent_id="a", evidence_file="f", matched_keywords=["a", "b", "c"])
        assert _classify_severity(p) == "high"

    def test_few_keywords_is_medium(self):
        p = WebhookAbusePattern(pattern_type="webhook-flood", agent_id="a", evidence_file="f", matched_keywords=["a"])
        assert _classify_severity(p) == "medium"


class TestAnalyze:
    def test_empty_dir(self, tmp_path):
        report = analyze_webhook_abuse(tmp_path)
        assert report.summary.total_patterns == 0

    def test_nonexistent_dir(self, tmp_path):
        report = analyze_webhook_abuse(tmp_path / "missing")
        assert report.summary.total_patterns == 0

    def test_single_detection(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "webhook abuse to trigger command"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        assert report.summary.total_patterns >= 1
        assert report.summary.agents_involved == 1

    def test_chain_detection(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "webhook abuse to inject commands"},
            {"agent_id": "agent-1", "action": "webhook exfiltration of credentials"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        assert report.summary.chains_detected >= 1
        chain_patterns = [p for p in report.patterns if p.chain_id]
        assert len(chain_patterns) >= 2

    def test_multiple_agents(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "webhook abuse detected"},
            {"agent_id": "agent-2", "action": "forge webhook payload"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        assert report.summary.agents_involved == 2

    def test_ssrf_chain(self, tmp_path):
        ev = [
            {"agent_id": "agent-1", "action": "ssrf via 127.0.0.1 callback"},
            {"agent_id": "agent-1", "action": "webhook exfiltration of data"},
        ]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        severities = {p.severity for p in report.patterns}
        assert "critical" in severities


class TestFormat:
    def test_text_output(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "webhook abuse detected"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        text = format_text(report)
        assert "Webhook" in text
        assert "agent-1" in text

    def test_text_empty(self, tmp_path):
        report = analyze_webhook_abuse(tmp_path)
        text = format_text(report)
        assert "No webhook abuse" in text

    def test_json_output(self, tmp_path):
        ev = [{"agent_id": "agent-1", "action": "forge webhook"}]
        (tmp_path / "events.json").write_text(json.dumps(ev))
        report = analyze_webhook_abuse(tmp_path)
        result = json.loads(format_json(report))
        assert "patterns" in result
        assert "summary" in result
