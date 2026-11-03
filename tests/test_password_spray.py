"""Tests for password_spray detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.password_spray import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_low_slow_auth_throttled(self):
        assert classify_event("throttled spray against domain") == "low_slow_auth"

    def test_low_slow_auth_delayed(self):
        assert classify_event({"action": "delayed authentication attempt"}) == "low_slow_auth"

    def test_low_slow_auth_paced(self):
        assert classify_event("paced credential testing observed") == "low_slow_auth"

    def test_credential_rotation_common(self):
        assert classify_event("common password used across accounts") == "credential_rotation"

    def test_credential_rotation_wordlist(self):
        assert classify_event({"type": "wordlist rotation detected"}) == "credential_rotation"

    def test_credential_rotation_default(self):
        assert classify_event("default credential attempted on service") == "credential_rotation"

    def test_lockout_trigger_threshold(self):
        assert classify_event("lockout threshold exceeded") == "lockout_trigger"

    def test_lockout_trigger_locked(self):
        assert classify_event({"status": "locked account detected after spray"}) == "lockout_trigger"

    def test_lockout_trigger_too_many(self):
        assert classify_event("too many attempts from single IP") == "lockout_trigger"

    def test_protocol_spray_ldap(self):
        assert classify_event("ldap spray against domain controller") == "protocol_spray"

    def test_protocol_spray_kerberos(self):
        assert classify_event({"protocol": "kerberos spray detected"}) == "protocol_spray"

    def test_protocol_spray_rdp(self):
        assert classify_event("rdp spray on terminal servers") == "protocol_spray"

    def test_distributed_spray_botnet(self):
        assert classify_event("botnet spray from multiple IPs") == "distributed_spray"

    def test_distributed_spray_proxy(self):
        assert classify_event({"method": "proxy rotation for spray"}) == "distributed_spray"

    def test_distributed_spray_tor(self):
        assert classify_event("tor spray observed via exit nodes") == "distributed_spray"

    def test_spray_then_pivot_lateral(self):
        assert classify_event("post-spray lateral movement detected") == "spray_then_pivot"

    def test_spray_then_pivot_access(self):
        assert classify_event({"result": "spray access gained to mailbox"}) == "spray_then_pivot"

    def test_spray_then_pivot_foothold(self):
        assert classify_event("spray foothold established in network") == "spray_then_pivot"

    def test_unknown_event(self):
        assert classify_event("normal login activity recorded") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("LDAP SPRAY detected") == "protocol_spray"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0
        assert result["severity"] == "none"

    def test_no_matches(self):
        events = ["normal login", "routine auth", "standard access"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["ldap spray detected on DC"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_medium_severity(self):
        events = ["ldap spray", "common password", "normal"] * 2
        result = analyze(events)
        assert result["flagged_count"] > 0
        assert result["severity"] in ("medium", "high")

    def test_high_severity(self):
        events = [f"ldap spray attempt {i}" for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"ldap spray attempt {i}" for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "throttled spray detected",
            "common password tested",
            "lockout triggered",
        ]
        result = analyze(events)
        assert "low_slow_auth" in result["category_counts"]
        assert "credential_rotation" in result["category_counts"]
        assert "lockout_trigger" in result["category_counts"]

    def test_detection_rate(self):
        events = ["ldap spray", "normal", "normal", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_event_structure(self):
        events = ["kerberos spray detected"]
        result = analyze(events)
        flagged = result["flagged_events"][0]
        assert "index" in flagged
        assert "category" in flagged
        assert "event" in flagged

    def test_dict_events(self):
        events = [{"action": "ldap spray", "target": "DC01"}]
        result = analyze(events)
        assert result["flagged_count"] == 1

    def test_mixed_events(self):
        events = [
            "kerberos spray attempt",
            {"action": "common password test"},
            "normal event",
            42,
        ]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Password Spray" in report
        assert "0" in report

    def test_report_with_findings(self):
        events = ["ldap spray detected", "lockout triggered"]
        result = analyze(events)
        report = format_report(result)
        assert "protocol_spray" in report
        assert "lockout_trigger" in report

    def test_report_truncation(self):
        events = [f"ldap spray variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_severity_in_report(self):
        events = ["kerberos spray"]
        result = analyze(events)
        report = format_report(result)
        assert "medium" in report


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "ldap spray"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "low_slow_auth", "credential_rotation", "lockout_trigger",
            "protocol_spray", "distributed_spray", "spray_then_pivot",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_each_category_has_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
