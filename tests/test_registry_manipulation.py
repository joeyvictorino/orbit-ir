"""Tests for registry_manipulation detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.registry_manipulation import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


# --- classify_event tests ---

class TestClassifyEvent:
    def test_persistence_run_key(self):
        event = {"action": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v malware"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "persistence_registry" in cats

    def test_persistence_runonce(self):
        event = {"action": "reg set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "persistence_registry" in cats

    def test_persistence_services(self):
        event = {"action": "reg add HKLM\\System\\CurrentControlSet\\Services\\backdoor"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "persistence_registry" in cats

    def test_security_bypass_defender(self):
        event = {"action": "Set DisableAntiSpyware = 1"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "security_bypass" in cats

    def test_security_bypass_uac(self):
        event = {"action": "EnableLUA = 0 to disable UAC"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "security_bypass" in cats

    def test_security_bypass_firewall(self):
        event = {"action": "EnableFirewall = 0"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "security_bypass" in cats

    def test_credential_access_sam(self):
        event = {"action": "SAM hive dump to extract credentials"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "credential_access" in cats

    def test_credential_access_reg_save(self):
        event = {"action": "reg save HKLM\\SAM sam.bak"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "credential_access" in cats

    def test_credential_access_lsa_secrets(self):
        event = {"action": "LSA secrets dump from registry"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "credential_access" in cats

    def test_config_tampering_policies(self):
        event = {"action": "reg add HKLM\\Software\\Policies\\something /v newval"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "config_tampering" in cats

    def test_config_tampering_proxy(self):
        event = {"action": "Proxy settings set to redirect traffic"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "config_tampering" in cats

    def test_evasion_clear_logs(self):
        event = {"action": "clear event log entries via registry"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "evasion_registry" in cats

    def test_evasion_hidden_files(self):
        event = {"action": "Set Hidden = 2 and SuperHidden = 1"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "evasion_registry" in cats

    def test_com_hijack_clsid(self):
        event = {"action": "Modified CLSID\\{00000000-0000-0000-0000-000000000000}"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "com_hijack" in cats

    def test_com_hijack_inprocserver(self):
        event = {"action": "InProcServer32 = C:\\malware\\evil.dll"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert "com_hijack" in cats

    def test_no_match(self):
        event = {"action": "normal user login event"}
        results = classify_event(event)
        assert results == []

    def test_empty_event(self):
        results = classify_event({})
        assert results == []

    def test_multiple_categories(self):
        event = {"action": "reg add HKLM\\CurrentVersion\\Run DisableAntiSpyware = 1"}
        results = classify_event(event)
        cats = [r["category"] for r in results]
        assert len(cats) >= 2

    def test_confidence_increases(self):
        event = {"action": "reg add HKLM\\Run registry persist autostart boot entry"}
        results = classify_event(event)
        persist = [r for r in results if r["category"] == "persistence_registry"]
        assert persist
        assert persist[0]["confidence"] > 0.3

    def test_details_populated(self):
        event = {"action": "SAM hive dump credentials"}
        results = classify_event(event)
        cred = [r for r in results if r["category"] == "credential_access"]
        assert cred
        assert cred[0]["details"] != ""

    def test_severity_matches_category(self):
        event = {"action": "DisableAntiSpyware = 1"}
        results = classify_event(event)
        bypass = [r for r in results if r["category"] == "security_bypass"]
        assert bypass
        assert bypass[0]["severity"] == "critical"


# --- analyze tests ---

class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged"] == 0

    def test_single_match(self):
        events = [{"action": "reg add HKLM\\CurrentVersion\\Run"}]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["flagged"] == 1

    def test_no_matches(self):
        events = [{"action": "normal operation"}, {"action": "another benign event"}]
        result = analyze(events)
        assert result["flagged"] == 0
        assert "no registry manipulation detected" in result["summary"]

    def test_mixed_events(self):
        events = [
            {"action": "reg add HKLM\\CurrentVersion\\Run"},
            {"action": "normal event"},
            {"action": "SAM hive dump"},
            {"action": "another normal event"},
        ]
        result = analyze(events)
        assert result["total_events"] == 4
        assert result["flagged"] == 2

    def test_categories_populated(self):
        events = [
            {"action": "reg add HKLM\\CurrentVersion\\Run"},
            {"action": "DisableAntiSpyware = 1"},
        ]
        result = analyze(events)
        assert "persistence_registry" in result["categories"]
        assert result["categories"]["persistence_registry"]["count"] >= 1

    def test_risk_score_range(self):
        events = [{"action": f"reg add HKLM\\Run item{i}"} for i in range(10)]
        result = analyze(events)
        assert 0 <= result["risk_score"] <= 1.0

    def test_summary_contains_top_categories(self):
        events = [
            {"action": "reg add HKLM\\Run persistence"},
            {"action": "SAM hive dump"},
        ]
        result = analyze(events)
        assert "top categories" in result["summary"]

    def test_all_categories_present(self):
        result = analyze([{"action": "nothing"}])
        for cat in CATEGORIES:
            assert cat in result["categories"]


# --- format_report tests ---

class TestFormatReport:
    def test_empty_report(self):
        analysis = analyze([])
        report = format_report(analysis)
        assert "Registry Manipulation Analysis" in report
        assert "Total events: 0" in report

    def test_report_with_findings(self):
        events = [{"action": "reg add HKLM\\CurrentVersion\\Run /v malware"}]
        analysis = analyze(events)
        report = format_report(analysis)
        assert "Flagged events: 1" in report
        assert "persistence_registry" in report

    def test_report_has_risk_score(self):
        analysis = analyze([{"action": "SAM hive dump"}])
        report = format_report(analysis)
        assert "Risk score:" in report

    def test_report_has_summary(self):
        analysis = analyze([{"action": "normal"}])
        report = format_report(analysis)
        assert "Summary:" in report


# --- load_events tests ---

class TestLoadEvents:
    def test_load_single_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"action": "test1"}, {"action": "test2"}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "single"}, f)
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
        events = load_events("/nonexistent/path")
        assert events == []

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
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


# --- Edge case tests ---

class TestEdgeCases:
    def test_missing_fields(self):
        event = {"timestamp": "2024-01-01T00:00:00Z"}
        results = classify_event(event)
        assert isinstance(results, list)

    def test_numeric_values(self):
        event = {"code": 12345, "pid": 999}
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
