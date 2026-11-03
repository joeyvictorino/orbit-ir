"""Tests for web shell detection module."""

import json
import os
import tempfile

from orbit_ir.web_shell import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_upload(self):
        assert classify_event("web shell upload detected on server") == "upload"

    def test_execution(self):
        assert classify_event("web shell execution of system commands") == "execution"

    def test_persistence(self):
        assert classify_event("web shell persistence mechanism found") == "persistence"

    def test_communication(self):
        assert classify_event("webshell callback to attacker") == "communication"

    def test_discovery(self):
        assert classify_event("webshell reconnaissance of internal network") == "discovery"

    def test_evasion(self):
        assert classify_event("webshell obfuscation techniques detected") == "evasion"

    def test_unknown(self):
        assert classify_event("normal http request") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "php shell upload found"}) == "upload"

    def test_case_insensitive(self):
        assert classify_event("WEB SHELL UPLOAD detected") == "upload"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_remote_code_execution(self):
        assert classify_event("remote code execution via uploaded script") == "execution"

    def test_hidden_web_shell(self):
        assert classify_event("hidden web shell found in uploads dir") == "persistence"

    def test_base64_shell(self):
        assert classify_event("base64 shell payload decoded") == "evasion"

    def test_fileless_webshell(self):
        assert classify_event("fileless webshell running in memory") == "evasion"

    def test_credential_dump(self):
        assert classify_event("credential dump webshell extracting passwords") == "discovery"

    def test_shell_reverse_connect(self):
        assert classify_event("shell reverse connect established") == "communication"


class TestAnalyze:
    def test_empty(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"
        assert r["detection_rate"] == 0.0

    def test_single_match(self):
        r = analyze(["web shell upload detected"])
        assert r["flagged_count"] == 1
        assert r["severity"] == "medium"

    def test_no_matches(self):
        r = analyze(["normal GET request", "static file served"])
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"

    def test_severity_high(self):
        events = [f"webshell command execution {i}" for i in range(6)]
        r = analyze(events)
        assert r["severity"] == "high"

    def test_severity_critical(self):
        events = [f"web shell upload {i}" for i in range(11)]
        r = analyze(events)
        assert r["severity"] == "critical"

    def test_category_counts(self):
        events = ["web shell upload found", "webshell command run", "shell upload detected"]
        r = analyze(events)
        assert r["category_counts"]["upload"] == 2
        assert r["category_counts"]["execution"] == 1

    def test_detection_rate(self):
        events = ["web shell upload", "normal request", "webshell callback", "static file"]
        r = analyze(events)
        assert r["detection_rate"] == 0.5

    def test_flagged_structure(self):
        r = analyze(["backdoor upload on host"])
        entry = r["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "upload"
        assert entry["event"] == "backdoor upload on host"


class TestFormatReport:
    def test_format_empty(self):
        r = analyze([])
        text = format_report(r)
        assert "Web Shell Detection Report" in text
        assert "0" in text

    def test_format_with_findings(self):
        r = analyze(["web shell upload", "remote code execution via webshell"])
        text = format_report(r)
        assert "Web Shell Detection Report" in text
        assert "upload" in text
        assert "execution" in text

    def test_format_truncation(self):
        events = [f"shell upload attempt {i}" for i in range(15)]
        r = analyze(events)
        text = format_report(r)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        r = analyze(["web shell upload", "normal request"])
        text = format_report(r)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["event1", "event2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a", "b"]
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "web shell upload"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [{"action": "web shell upload"}]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) >= 5, f"{cat} has fewer than 5 patterns"

    def test_category_names(self):
        expected = {"upload", "execution", "persistence",
                    "communication", "discovery", "evasion"}
        assert set(CATEGORIES.keys()) == expected
