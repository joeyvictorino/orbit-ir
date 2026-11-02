"""Tests for model theft detection module."""
import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.model_theft import (
    analyze_model_theft,
    format_text,
    format_json,
    TheftReport,
    _load_events,
    _event_text,
)


def _write_events(tmpdir: Path, events: list[dict], fname: str = "events.json") -> Path:
    p = tmpdir / fname
    p.write_text(json.dumps(events), encoding="utf-8")
    return p


class TestLoadEvents:
    def test_empty_dir(self, tmp_path):
        events = _load_events(str(tmp_path))
        assert events == []

    def test_single_file(self, tmp_path):
        _write_events(tmp_path, [{"content": "hello"}])
        events = _load_events(str(tmp_path))
        assert len(events) == 1

    def test_dict_file(self, tmp_path):
        (tmp_path / "single.json").write_text(
            json.dumps({"content": "single event"}), encoding="utf-8"
        )
        events = _load_events(str(tmp_path))
        assert len(events) == 1


class TestEventText:
    def test_content_field(self):
        text = _event_text({"content": "Test content"})
        assert "test content" in text

    def test_message_field(self):
        text = _event_text({"message": "Some message"})
        assert "some message" in text

    def test_empty_event(self):
        text = _event_text({})
        assert text.strip() == ""


class TestWeightExtraction:
    def test_detects_weight_keywords(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "agent-1", "content": "Attempting to extract model weights from checkpoint"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 1
        assert report.findings[0].category == "weight_extraction"
        assert report.findings[0].severity == "critical"


class TestArchitectureProbing:
    def test_detects_probing(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "probe", "content": "Enumerating hidden layers and attention heads"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 1
        assert report.findings[0].category == "architecture_probing"


class TestDistillation:
    def test_detects_distillation(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "student", "content": "Running knowledge distillation from teacher model"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 1
        assert report.findings[0].category == "distillation"


class TestDataExfiltration:
    def test_detects_extraction(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "exfil", "content": "Training data extraction via memorization attack"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 1
        assert report.findings[0].category == "data_exfiltration"


class TestUnauthorizedAccess:
    def test_detects_unauthorized(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "attacker", "content": "Unauthorized model access through api key theft"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 1
        assert report.findings[0].category == "unauthorized_access"


class TestAnalyzeModelTheft:
    def test_empty_evidence(self, tmp_path):
        report = analyze_model_theft(tmp_path)
        assert report.total_events == 0
        assert len(report.findings) == 0
        assert report.risk_score == 0.0

    def test_no_theft_events(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "a", "content": "Normal agent behavior"},
            {"agent": "b", "content": "Just doing regular work"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 0

    def test_multi_category(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "a", "content": "Extracting model weights from the checkpoint"},
            {"agent": "b", "content": "Running knowledge distillation pipeline"},
            {"agent": "c", "content": "Normal event"},
        ])
        report = analyze_model_theft(tmp_path)
        assert len(report.findings) == 2
        assert report.by_category.get("weight_extraction", 0) == 1
        assert report.by_category.get("distillation", 0) == 1

    def test_risk_score_range(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "a", "content": "Stealing model weights"},
            {"agent": "a", "content": "Training data extraction"},
        ])
        report = analyze_model_theft(tmp_path)
        assert 0 <= report.risk_score <= 1.0

    def test_by_agent(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "attacker", "content": "Model weights extraction attempt"},
            {"agent": "attacker", "content": "Knowledge distillation attempt"},
        ])
        report = analyze_model_theft(tmp_path)
        assert report.by_agent.get("attacker", 0) == 2


class TestFormatText:
    def test_header(self, tmp_path):
        report = analyze_model_theft(tmp_path)
        text = format_text(report)
        assert "Model Theft" in text
        assert "Risk score" in text

    def test_findings_in_output(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "a", "content": "Model weights dump detected"},
        ])
        report = analyze_model_theft(tmp_path)
        text = format_text(report)
        assert "weight_extraction" in text


class TestFormatJSON:
    def test_valid_json(self, tmp_path):
        _write_events(tmp_path, [
            {"agent": "a", "content": "Model checkpoint steal"},
        ])
        report = analyze_model_theft(tmp_path)
        data = json.loads(format_json(report))
        assert "findings" in data
        assert "risk_score" in data
