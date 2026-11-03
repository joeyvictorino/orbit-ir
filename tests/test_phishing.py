"""Tests for phishing campaign detection module."""

import pytest
from orbit_ir.phishing import classify_event, analyze, format_report, CATEGORIES


class TestClassifyEvent:
    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_unrelated_text(self):
        assert classify_event("normal web traffic observed") == "unknown"

    def test_dict_event(self):
        event = {"description": "spear phishing attack detected targeting CEO"}
        assert classify_event(event) == "spear_phishing"


class TestSpearPhishing:
    def test_spear_phishing_attack(self):
        assert classify_event("spear phishing attack detected") == "spear_phishing"

    def test_targeted_phishing_email(self):
        assert classify_event("targeted phishing email to user") == "spear_phishing"

    def test_personalized_phish(self):
        assert classify_event("personalized phish with user details") == "spear_phishing"

    def test_spear_phishing_campaign(self):
        assert classify_event("spear-phishing campaign against org") == "spear_phishing"

    def test_researched_target(self):
        assert classify_event("researched target phishing using LinkedIn data") == "spear_phishing"


class TestCredentialHarvest:
    def test_credential_harvesting_page(self):
        assert classify_event("credential harvesting page discovered") == "credential_harvest"

    def test_fake_login_portal(self):
        assert classify_event("fake login portal mimicking corporate SSO") == "credential_harvest"

    def test_password_harvesting(self):
        assert classify_event("password harvesting form on phishing domain") == "credential_harvest"

    def test_credential_capture_proxy(self):
        assert classify_event("credential capture proxy intercepting logins") == "credential_harvest"

    def test_harvested_user_credentials(self):
        assert classify_event("harvested user credentials from fake site") == "credential_harvest"


class TestBusinessEmailCompromise:
    def test_bec_attack(self):
        assert classify_event("bec attack targeting finance department") == "business_email_compromise"

    def test_ceo_fraud(self):
        assert classify_event("ceo fraud email requesting wire transfer") == "business_email_compromise"

    def test_wire_transfer_fraud(self):
        assert classify_event("wire transfer fraud email detected") == "business_email_compromise"

    def test_invoice_fraud(self):
        assert classify_event("invoice fraud phishing with modified details") == "business_email_compromise"

    def test_vendor_email_compromise(self):
        assert classify_event("vendor email compromise with spoofed sender") == "business_email_compromise"


class TestSmishing:
    def test_sms_phishing(self):
        assert classify_event("sms phishing attack via bulk texts") == "smishing"

    def test_smishing_campaign(self):
        assert classify_event("smishing campaign targeting bank customers") == "smishing"

    def test_text_message_phishing(self):
        assert classify_event("text message phishing with fake link") == "smishing"

    def test_malicious_sms_link(self):
        assert classify_event("malicious sms link to credential page") == "smishing"

    def test_cellular_phishing(self):
        assert classify_event("cellular phishing attempt detected") == "smishing"


class TestWhaling:
    def test_whaling_attack(self):
        assert classify_event("whaling attack executive level threat") == "whaling"

    def test_executive_whaling(self):
        assert classify_event("executive whaling campaign launched") == "whaling"

    def test_csuite_phishing(self):
        assert classify_event("c-suite phishing attempt via email") == "whaling"

    def test_senior_management(self):
        assert classify_event("senior management phishing detected") == "whaling"

    def test_vip_targeted(self):
        assert classify_event("vip targeted phishing with personal data") == "whaling"


class TestClonePhishing:
    def test_clone_phishing(self):
        assert classify_event("clone phishing duplicate of legitimate email") == "clone_phishing"

    def test_cloned_email_attack(self):
        assert classify_event("cloned email attack with malicious attachment") == "clone_phishing"

    def test_replicated_email(self):
        assert classify_event("replicated email phishing detected") == "clone_phishing"

    def test_resent_email(self):
        assert classify_event("resent email with payload embedded") == "clone_phishing"

    def test_mimicked_thread(self):
        assert classify_event("mimicked email thread attack using spoofed reply") == "clone_phishing"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_phishing(self):
        events = ["normal traffic", "user login", "page load"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_detection(self):
        events = ["normal traffic", "spear phishing attack detected", "page load"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_high_severity(self):
        events = [f"spear phishing attack {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"credential harvesting page {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "spear phishing attack found",
            "credential harvesting page on domain",
            "spear phishing attack again",
        ]
        result = analyze(events)
        assert result["category_counts"]["spear_phishing"] == 2
        assert result["category_counts"]["credential_harvest"] == 1

    def test_detection_rate(self):
        events = ["spear phishing attack found", "normal traffic"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5


class TestFormatReport:
    def test_format_report(self):
        result = analyze(["spear phishing attack detected", "normal traffic"])
        report = format_report(result)
        assert "Phishing Campaign Detection Report" in report
        assert "spear_phishing" in report

    def test_format_report_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Flagged:           0" in report
