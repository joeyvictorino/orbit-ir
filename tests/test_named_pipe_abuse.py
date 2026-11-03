"""Tests for named_pipe_abuse detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.named_pipe_abuse import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


# --- classify_event tests ---

class TestClassifyEvent:
    def test_pipe_impersonation_token(self):
        event = {"action": "impersonate named pipe client token"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_impersonation" in cats

    def test_pipe_impersonation_api(self):
        event = {"action": "ImpersonateNamedPipeClient called on target pipe"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_impersonation" in cats

    def test_pipe_impersonation_potato(self):
        event = {"action": "JuicyPotato exploit escalation via pipe"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_impersonation" in cats

    def test_pipe_relay_ntlm(self):
        event = {"action": "NTLM relay via pipe IPC channel"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_relay" in cats

    def test_pipe_relay_printerbug(self):
        event = {"action": "PrinterBug relay coerce attack"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_relay" in cats

    def test_pipe_relay_petitpotam(self):
        event = {"action": "PetitPotam coerce relay via LSARPC"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_relay" in cats

    def test_pipe_privesc(self):
        event = {"action": "pipe privilege escalation to SYSTEM"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_privilege_escalation" in cats

    def test_pipe_privesc_dacl(self):
        event = {"action": "named pipe DACL bypass abuse weak permissions"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_privilege_escalation" in cats

    def test_pipe_covert_channel(self):
        event = {"action": "covert pipe communication channel established"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_covert_channel" in cats

    def test_pipe_covert_c2(self):
        event = {"action": "named pipe tunnel for c2 command and control"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_covert_channel" in cats

    def test_pipe_covert_beacon(self):
        event = {"action": "beacon communicates callback via pipe IPC channel"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_covert_channel" in cats

    def test_pipe_injection(self):
        event = {"action": "inject payload via named pipe"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_injection" in cats

    def test_pipe_injection_shellcode(self):
        event = {"action": "pipe inject shellcode into process"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_injection" in cats

    def test_pipe_enumeration(self):
        event = {"action": "enumerate named pipe endpoints"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_enumeration" in cats

    def test_pipe_enumeration_pipelist(self):
        event = {"action": "pipelist scan named pipe endpoints"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "pipe_enumeration" in cats

    def test_no_match(self):
        event = {"action": "normal file read operation"}
        results = classify_event(event)
        assert results == []

    def test_empty_event(self):
        results = classify_event({})
        assert results == []

    def test_multiple_categories(self):
        event = {"action": "impersonate named pipe and inject payload via pipe exploit"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert len(cats) >= 2

    def test_confidence_scaling(self):
        event = {"action": "pipe impersonation steal client token identity impersonate"}
        results = classify_event(event)
        imp = [r for r in results if r["category"] == "pipe_impersonation"]
        assert imp
        assert imp[0]["confidence"] >= 0.3

    def test_details_populated(self):
        event = {"action": "ImpersonateNamedPipeClient token theft"}
        results = classify_event(event)
        imp = [r for r in results if r["category"] == "pipe_impersonation"]
        assert imp
        assert imp[0]["details"] != ""

    def test_severity_correct(self):
        event = {"action": "pipe enumeration scan"}
        results = classify_event(event)
        enum_r = [r for r in results if r["category"] == "pipe_enumeration"]
        if enum_r:
            assert enum_r[0]["severity"] == "medium"


# --- analyze tests ---

class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged"] == 0

    def test_single_match(self):
        events = [{"action": "impersonate named pipe client"}]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["flagged"] == 1

    def test_no_matches(self):
        events = [{"action": "normal"}, {"action": "benign"}]
        result = analyze(events)
        assert result["flagged"] == 0
        assert "no named pipe abuse detected" in result["summary"]

    def test_mixed_events(self):
        events = [
            {"action": "impersonate named pipe client"},
            {"action": "normal event"},
            {"action": "NTLM relay via pipe"},
            {"action": "benign action"},
        ]
        result = analyze(events)
        assert result["total_events"] == 4
        assert result["flagged"] == 2

    def test_categories_in_result(self):
        events = [{"action": "enumerate named pipe list"}]
        result = analyze(events)
        assert "pipe_enumeration" in result["categories"]

    def test_risk_score_bounded(self):
        events = [{"action": f"impersonate pipe client {i}"} for i in range(20)]
        result = analyze(events)
        assert 0 <= result["risk_score"] <= 1.0

    def test_summary_top_categories(self):
        events = [
            {"action": "impersonate pipe client"},
            {"action": "NTLM relay via pipe IPC"},
        ]
        result = analyze(events)
        assert "top categories" in result["summary"]

    def test_all_categories_present(self):
        result = analyze([{"action": "nothing"}])
        for cat in CATEGORIES:
            assert cat in result["categories"]

    def test_event_count_limited(self):
        events = [{"action": f"impersonate pipe client token {i}"} for i in range(20)]
        result = analyze(events)
        for cat_data in result["categories"].values():
            assert len(cat_data["events"]) <= 10


# --- format_report tests ---

class TestFormatReport:
    def test_empty_report(self):
        analysis = analyze([])
        report = format_report(analysis)
        assert "Named Pipe Abuse Analysis" in report
        assert "Total events: 0" in report

    def test_report_with_findings(self):
        events = [{"action": "impersonate named pipe client token"}]
        analysis = analyze(events)
        report = format_report(analysis)
        assert "Flagged events: 1" in report
        assert "pipe_impersonation" in report

    def test_report_has_risk(self):
        analysis = analyze([{"action": "pipe relay attack"}])
        report = format_report(analysis)
        assert "Risk score:" in report

    def test_report_has_summary(self):
        analysis = analyze([{"action": "nothing"}])
        report = format_report(analysis)
        assert "Summary:" in report


# --- load_events tests ---

class TestLoadEvents:
    def test_load_single_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"a": 1}, {"a": 2}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "one"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_directory(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                p = os.path.join(d, f"ev{i}.json")
                with open(p, "w") as f:
                    json.dump([{"action": f"event{i}"}], f)
            events = load_events(d)
        assert len(events) == 3

    def test_load_nonexistent(self):
        events = load_events("/no/such/path")
        assert events == []

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{{{bad json")
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert events == []

    def test_load_non_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("not json")
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert events == []


# --- Edge cases ---

class TestEdgeCases:
    def test_missing_fields(self):
        event = {"ts": "2024-01-01"}
        results = classify_event(event)
        assert isinstance(results, list)

    def test_numeric_values(self):
        event = {"code": 42, "port": 445}
        results = classify_event(event)
        assert isinstance(results, list)

    def test_all_categories_have_severity(self):
        for cat, info in CATEGORIES.items():
            assert "severity" in info
            assert info["severity"] in ("critical", "high", "medium", "low")

    def test_all_categories_have_patterns(self):
        for cat, info in CATEGORIES.items():
            assert "patterns" in info
            assert len(info["patterns"]) > 0
