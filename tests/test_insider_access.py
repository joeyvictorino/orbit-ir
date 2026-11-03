import json
import os
import tempfile
import pytest
from orbit_ir.insider_access import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_unauthorized_access(self):
        assert classify_event("unauthorized access to database detected") == "unauthorized_access"

    def test_access_violation(self):
        assert classify_event("access violation logged for user") == "unauthorized_access"

    def test_unauthorized_login(self):
        assert classify_event("unauthorized login attempt from external IP") == "unauthorized_access"

    def test_privilege_misuse(self):
        assert classify_event("privilege misuse by admin account") == "privilege_misuse"

    def test_admin_abuse(self):
        assert classify_event("admin abuse of system resources") == "privilege_misuse"

    def test_root_access_misuse(self):
        assert classify_event("root access misuse detected on server") == "privilege_misuse"

    def test_data_hoarding(self):
        assert classify_event("data hoarding behavior detected") == "data_hoarding"

    def test_bulk_data_download(self):
        assert classify_event("bulk data download initiated") == "data_hoarding"

    def test_mass_file_copy(self):
        assert classify_event("mass file copy operation detected") == "data_hoarding"

    def test_off_hours_access(self):
        assert classify_event("off hours access to production system") == "off_hours_access"

    def test_late_night_login(self):
        assert classify_event("late night login to sensitive system") == "off_hours_access"

    def test_weekend_access(self):
        assert classify_event("weekend access anomaly flagged") == "off_hours_access"

    def test_security_policy_breach(self):
        assert classify_event("security policy breach identified") == "policy_violation"

    def test_separation_of_duties(self):
        assert classify_event("separation of duties breach detected") == "policy_violation"

    def test_least_privilege_violation(self):
        assert classify_event("least privilege violation found") == "policy_violation"

    def test_account_sharing(self):
        assert classify_event("account sharing detected between users") == "account_sharing"

    def test_impossible_travel(self):
        assert classify_event("impossible travel login detected") == "account_sharing"

    def test_simultaneous_session(self):
        assert classify_event("simultaneous session from two locations") == "account_sharing"

    def test_unknown(self):
        assert classify_event("normal user logged in") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "unauthorized access detected"}) == "unauthorized_access"

    def test_case_insensitive(self):
        assert classify_event("UNAUTHORIZED ACCESS Detected") == "unauthorized_access"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["unauthorized access found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["normal login", "regular activity"])
        assert result["flagged_count"] == 0

    def test_severity_high(self):
        events = [f"unauthorized access event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"unauthorized access event {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["unauthorized access detected", "privilege misuse found", "unauthorized access again"]
        result = analyze(events)
        assert result["category_counts"]["unauthorized_access"] == 2
        assert result["category_counts"]["privilege_misuse"] == 1

    def test_detection_rate(self):
        result = analyze(["unauthorized access", "normal", "privilege misuse", "safe"])
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["unauthorized access flagged"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "unauthorized_access"
        assert entry["event"] == "unauthorized access flagged"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Insider Access" in text

    def test_format_with_findings(self):
        result = analyze(["unauthorized access detected"])
        text = format_report(result)
        assert "unauthorized_access" in text

    def test_format_truncation(self):
        events = [f"unauthorized access event {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["unauthorized access", "normal"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "test"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"category {cat} has no patterns"

    def test_category_names(self):
        expected = {"unauthorized_access", "privilege_misuse", "data_hoarding", "off_hours_access", "policy_violation", "account_sharing"}
        assert set(CATEGORIES.keys()) == expected
