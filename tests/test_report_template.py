"""Tests for orbit_ir.report_template — customizable report generation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from orbit_ir.report_template import (
    TemplateReporter,
    list_templates,
    show_template,
    format_template_list,
    BUILTIN_TEMPLATES,
)


@pytest.fixture
def tmp(tmp_path):
    return tmp_path


def _make_evidence(tmp, events):
    d = tmp / "evidence"
    d.mkdir(exist_ok=True)
    (d / "events.json").write_text(json.dumps(events), encoding="utf-8")
    return d


# --- Template listing ---

def test_list_templates_returns_all():
    templates = list_templates()
    names = {t["name"] for t in templates}
    assert names == {"full", "brief", "technical", "compliance"}


def test_show_template_builtin():
    tmpl = show_template("full")
    assert tmpl is not None
    assert "{{title}}" in tmpl


def test_show_template_unknown():
    assert show_template("nonexistent") is None


def test_format_template_list():
    text = format_template_list(list_templates())
    assert "Available templates:" in text
    assert "full" in text
    assert "brief" in text


# --- Rendering ---

def test_render_full_template(tmp):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "agent": "a1", "action": "read data", "severity": "high", "target": "db1"},
        {"timestamp": "2025-01-01T01:00:00Z", "agent": "a2", "action": "escalate privs", "severity": "critical", "target": "host1"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    output = reporter.render("full", evidence_dir, title="Test Report")
    assert "Test Report" in output
    assert "2" in output  # total events
    assert "a1" in output or "a2" in output


def test_render_brief_template(tmp):
    events = [
        {"timestamp": "t1", "agent": "bot", "action": "scan", "severity": "medium"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    output = reporter.render("brief", evidence_dir)
    assert "Executive Brief" in output
    assert "1" in output


def test_render_technical_template(tmp):
    events = [
        {"timestamp": "t1", "agent": "a", "action": "exploit", "severity": "critical", "target": "sys1"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    output = reporter.render("technical", evidence_dir)
    assert "Technical Report" in output
    assert "sys1" in output


def test_render_compliance_template(tmp):
    events = [
        {"timestamp": "t1", "agent": "a", "action": "login", "severity": "low"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    output = reporter.render("compliance", evidence_dir)
    assert "Compliance Report" in output


# --- Custom template ---

def test_render_custom_template_file(tmp):
    events = [{"timestamp": "t", "agent": "bot", "action": "ping", "severity": "info"}]
    evidence_dir = _make_evidence(tmp, events)
    custom = tmp / "my.tmpl"
    custom.write_text("Report: {{title}} has {{total_events}} events by {{unique_agents}} agents.", encoding="utf-8")
    reporter = TemplateReporter()
    output = reporter.render(str(custom), evidence_dir, title="Custom")
    assert "Custom" in output
    assert "1 events" in output
    assert "1 agents" in output


def test_render_unknown_template_raises(tmp):
    evidence_dir = _make_evidence(tmp, [])
    reporter = TemplateReporter()
    with pytest.raises(ValueError, match="Unknown template"):
        reporter.render("nosuchtemplate", evidence_dir)


# --- Variable substitution ---

def test_variables_severity_summary(tmp):
    events = [
        {"timestamp": "t", "agent": "a", "action": "x", "severity": "critical"},
        {"timestamp": "t", "agent": "a", "action": "x", "severity": "critical"},
        {"timestamp": "t", "agent": "a", "action": "x", "severity": "low"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    reporter.load_events(evidence_dir)
    v = reporter.build_variables()
    assert "Critical: 2" in v["severity_summary"]
    assert "Low: 1" in v["severity_summary"]


def test_variables_technique_summary(tmp):
    events = [
        {"timestamp": "t", "agent": "a", "action": "x", "techniques": ["T1059", "T1071"]},
        {"timestamp": "t", "agent": "a", "action": "x", "techniques": ["T1059"]},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    reporter.load_events(evidence_dir)
    v = reporter.build_variables()
    assert "T1059: 2" in v["technique_summary"]


def test_variables_empty_evidence(tmp):
    evidence_dir = _make_evidence(tmp, [])
    reporter = TemplateReporter()
    reporter.load_events(evidence_dir)
    v = reporter.build_variables()
    assert v["total_events"] == "0"
    assert v["unique_agents"] == "0"
    assert "No events" in v["severity_summary"]


def test_variables_recommendations_critical(tmp):
    events = [
        {"timestamp": "t", "agent": "a", "action": "x", "severity": "critical"},
    ]
    evidence_dir = _make_evidence(tmp, events)
    reporter = TemplateReporter()
    reporter.load_events(evidence_dir)
    v = reporter.build_variables()
    assert "URGENT" in v["recommendations"]


# --- HTML conversion ---

def test_to_html(tmp):
    reporter = TemplateReporter()
    md = "# Title\n\n## Section\n\n- item1\n- item2\n\nParagraph."
    html = reporter.to_html(md)
    assert "<h1>" in html
    assert "<h2>" in html
    assert "<li>" in html
    assert "<p>" in html
    assert "</html>" in html


# --- Single file loading ---

def test_load_single_file(tmp):
    f = tmp / "events.json"
    f.write_text(json.dumps([{"timestamp": "t", "agent": "a", "action": "x"}]), encoding="utf-8")
    reporter = TemplateReporter()
    reporter.load_events(f)
    assert len(reporter.events) == 1
