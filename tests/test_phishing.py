"""Tests for phishing detection module."""

import json
import os
import tempfile

from orbit_ir.phishing import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_spear_phishing(self):
        assert classify_event("spear phishing email targeting CFO") == "spear_phishing"

    def test_credential_harvesting(self):
        assert classify_event("credential harvesting page detected") == "credential_harvesting"

    def test_url_spoofing(self):
        assert classify_event("url spoofing in email link") == "url_spoofing"

    def test_homograph_attack(self):
        assert classify_event("idn homograph domain detected") == "homograph_attack"

    def test_email_impersonation(self):
        assert classify_event("display name spoofing from attacker") == "email_impersonation"

    def test_smishing(self):
        assert classify_event("smishing attack via text message") == "smishing"

    def test_vishing(self):
        assert classify_event("vishing call from spoofed number") == "vishing"

    def test_watering_hole(self):
        assert classify_event("watering hole attack on partner site") == "watering_hole"

    def test_unknown(self):
        assert classify_event("normal email received") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "spear phishing detected"}) == "spear_phishing"

    def test_case_insensitive(self):
        assert classify_event("CREDENTIAL HARVESTING attempt") == "credential_harvesting"

    def test_non_string_non_dict(self):
        assert classify_event(123) == "unknown"

    def test_bec_attack(self):
        assert classify_event("bec attack impersonating CEO") == "spear_phishing"

    def test_fake_login(self):
        assert classify_event("fake login page hosted on compromised server") == "credential_harvesting"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_single_match(self):
        result = analyze(["spear phishing attempt"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"credential harvesting {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"phishing attempt {i}" for i in range(11)]
        # "phishing" alone doesn't match any indicator, need real ones
        events = [f"spear phishing {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_no_matches(self):
        result = analyze(["meeting invite", "calendar update", "file shared"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_category_counts(self):
        events = ["spear phishing email", "vishing call", "spear phishing again"]
        result = analyze(events)
        assert result["category_counts"]["spear_phishing"] == 2
        assert result["category_counts"]["vishing"] == 1

    def test_detection_rate(self):
        events = ["credential harvesting", "normal", "vishing call", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["smishing detected"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "smishing"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Phishing Attack Detection Report" in text
        assert "none" in text

    def test_format_with_findings(self):
        result = analyze(["spear phishing email", "vishing call"])
        text = format_report(result)
        assert "spear_phishing" in text
        assert "vishing" in text

    def test_format_truncation(self):
        events = [f"credential harvesting {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["phish1", "phish2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["phish1", "phish2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a"]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a"]
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "phishing"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [{"type": "phishing"}]
        finally:
            os.unlink(path)
