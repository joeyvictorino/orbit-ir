"""Tests for environment variable manipulation detection."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from orbit_ir.env_manipulation import (
    analyze_env_manipulation,
    format_text,
    format_json,
    _classify_event,
    _analyze,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_env_override(self):
        event = {"message": "export HOME=/tmp/evil"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "env_override" in cats

    def test_env_injection(self):
        event = {"message": "injected into env variable VALUE=$(cat /etc/passwd)"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "env_injection" in cats

    def test_path_hijack(self):
        event = {"message": "PATH=/tmp/bin:/usr/bin"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "path_hijack" in cats

    def test_credential_swap(self):
        event = {"message": "API_KEY=sk-evil-key-12345"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "credential_swap" in cats

    def test_config_poison(self):
        event = {"message": "DEBUG=true DISABLE_AUTH=true"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "config_poison" in cats

    def test_no_match(self):
        event = {"message": "normal log entry with no suspicious content"}
        matches = _classify_event(event)
        assert len(matches) == 0

    def test_ld_preload(self):
        event = {"message": "LD_PRELOAD=/tmp/evil.so"}
        matches = _classify_event(event)
        cats = [m[0] for m in matches]
        assert "path_hijack" in cats


class TestAnalyze:
    def test_empty(self):
        report = _analyze([])
        assert report.total_events == 0
        assert report.risk_score == 0.0
        assert report.risk_level == "none"

    def test_single_event(self):
        events = [{"message": "export HOME=/tmp/evil"}]
        report = _analyze(events)
        assert report.total_events == 1
        assert report.manipulation_events == 1

    def test_mixed_events(self):
        events = [
            {"message": "export HOME=/tmp/evil"},
            {"message": "normal log entry"},
            {"message": "PATH=/tmp:/usr/bin"},
        ]
        report = _analyze(events)
        assert report.total_events == 3
        assert report.manipulation_events == 2

    def test_risk_score_range(self):
        events = [{"message": "LD_PRELOAD=/tmp/evil.so"}]
        report = _analyze(events)
        assert 0.0 <= report.risk_score <= 1.0

    def test_categories_populated(self):
        events = [{"message": "API_KEY=evil_key_value"}]
        report = _analyze(events)
        assert len(report.categories) == len(CATEGORIES)

    def test_top_variables(self):
        events = [
            {"message": "HOME=/tmp/a"},
            {"message": "HOME=/tmp/b"},
            {"message": "PATH=/evil"},
        ]
        report = _analyze(events)
        if report.top_variables:
            assert report.top_variables[0]["count"] >= 1


class TestAnalyzeFromDir:
    def test_with_evidence_dir(self):
        with tempfile.TemporaryDirectory() as td:
            data = [
                {"timestamp": "2024-01-01T00:00:00Z", "message": "PATH=/tmp/evil"},
                {"timestamp": "2024-01-01T00:01:00Z", "message": "normal activity"},
            ]
            Path(td, "events.json").write_text(json.dumps(data))
            report = analyze_env_manipulation(td)
            assert report.total_events == 2

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            report = analyze_env_manipulation(td)
            assert report.total_events == 0

    def test_missing_dir(self):
        report = analyze_env_manipulation("/nonexistent/path")
        assert report.total_events == 0

    def test_path_object(self):
        with tempfile.TemporaryDirectory() as td:
            data = [{"message": "LD_PRELOAD=/tmp/evil.so"}]
            Path(td, "ev.json").write_text(json.dumps(data))
            report = analyze_env_manipulation(Path(td))
            assert report.total_events == 1


class TestFormat:
    def _sample_report(self):
        events = [
            {"message": "export HOME=/tmp/evil", "timestamp": "2024-01-01T00:00:00Z"},
            {"message": "PATH=/tmp:/usr/bin"},
            {"message": "API_KEY=evil_key"},
        ]
        return _analyze(events)

    def test_format_text(self):
        report = self._sample_report()
        text = format_text(report)
        assert "Environment Variable Manipulation" in text
        assert "Risk score" in text

    def test_format_json(self):
        report = self._sample_report()
        j = format_json(report)
        parsed = json.loads(j)
        assert "total_events" in parsed
        assert "risk_score" in parsed
        assert "categories" in parsed

    def test_format_text_empty(self):
        report = _analyze([])
        text = format_text(report)
        assert "Total events: 0" in text

    def test_format_json_valid(self):
        report = _analyze([])
        j = format_json(report)
        parsed = json.loads(j)
        assert parsed["risk_level"] == "none"
