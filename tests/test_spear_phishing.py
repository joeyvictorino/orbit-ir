"""Tests for spear_phishing detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.spear_phishing import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_personalized_lure_spear_phish(self):
        assert classify_event("spear phish targeting executive") == "personalized_lure"

    def test_personalized_lure_targeted_message(self):
        assert classify_event({"action": "targeted message sent to CFO"}) == "personalized_lure"

    def test_personalized_lure_custom(self):
        assert classify_event("custom lure crafted for victim") == "personalized_lure"

    def test_social_recon_linkedin(self):
        assert classify_event("linkedin scrape of company employees") == "social_recon"

    def test_social_recon_orgchart(self):
        assert classify_event({"type": "org chart harvest completed"}) == "social_recon"

    def test_social_recon_osint(self):
        assert classify_event("osint gathering on target organization") == "social_recon"

    def test_credential_harvest_fake_login(self):
        assert classify_event("fake login page deployed") == "credential_harvest"

    def test_credential_harvest_evilginx(self):
        assert classify_event({"tool": "evilginx proxy configured"}) == "credential_harvest"

    def test_credential_harvest_oauth(self):
        assert classify_event("oauth phish consent page created") == "credential_harvest"

    def test_brand_impersonation_lookalike(self):
        assert classify_event("lookalike domain registered") == "brand_impersonation"

    def test_brand_impersonation_spoof(self):
        assert classify_event({"action": "display name spoof in email"}) == "brand_impersonation"

    def test_brand_impersonation_homoglyph(self):
        assert classify_event("homoglyph domain for microsoft") == "brand_impersonation"

    def test_attachment_payload_macro(self):
        assert classify_event("macro payload embedded in document") == "attachment_payload"

    def test_attachment_payload_dropper(self):
        assert classify_event({"type": "dropper document attached"}) == "attachment_payload"

    def test_attachment_payload_html_smuggling(self):
        assert classify_event("html smuggling payload delivered") == "attachment_payload"

    def test_callback_phishing_vishing(self):
        assert classify_event("vishing pretext call scheduled") == "callback_phishing"

    def test_callback_phishing_smishing(self):
        assert classify_event({"method": "smishing lure sent via SMS"}) == "callback_phishing"

    def test_callback_phishing_quishing(self):
        assert classify_event("quishing QR code generated") == "callback_phishing"

    def test_unknown_event(self):
        assert classify_event("normal email activity logged") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("SPEAR PHISH detected") == "personalized_lure"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0
        assert result["severity"] == "none"

    def test_no_matches(self):
        events = ["normal email", "routine message", "standard activity"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["spear phish attempt detected"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_medium_severity(self):
        events = ["spear phish", "fake login", "normal"] * 2
        result = analyze(events)
        assert result["flagged_count"] > 0
        assert result["severity"] in ("medium", "high")

    def test_high_severity(self):
        events = [f"spear phish attempt {i}" for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"spear phish attempt {i}" for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "spear phish targeted",
            "linkedin scrape completed",
            "fake login deployed",
        ]
        result = analyze(events)
        assert "personalized_lure" in result["category_counts"]
        assert "social_recon" in result["category_counts"]
        assert "credential_harvest" in result["category_counts"]

    def test_detection_rate(self):
        events = ["spear phish", "normal", "normal", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_event_structure(self):
        events = ["spear phish attempt"]
        result = analyze(events)
        flagged = result["flagged_events"][0]
        assert "index" in flagged
        assert "category" in flagged
        assert "event" in flagged

    def test_dict_events(self):
        events = [{"action": "spear phish", "target": "CEO"}]
        result = analyze(events)
        assert result["flagged_count"] == 1

    def test_mixed_events(self):
        events = [
            "spear phish attempt",
            {"action": "linkedin scrape"},
            "normal event",
            42,
        ]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Spear Phishing" in report
        assert "0" in report

    def test_report_with_findings(self):
        events = ["spear phish attempt detected", "fake login page found"]
        result = analyze(events)
        report = format_report(result)
        assert "personalized_lure" in report
        assert "credential_harvest" in report

    def test_report_truncation(self):
        events = [f"spear phish variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_severity_in_report(self):
        events = ["spear phish"]
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
            json.dump({"action": "spear phish"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "personalized_lure", "social_recon", "credential_harvest",
            "brand_impersonation", "attachment_payload", "callback_phishing",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_each_category_has_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
