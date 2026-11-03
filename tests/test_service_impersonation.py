"""Tests for service_impersonation detection module."""

import json
import os
import tempfile

from orbit_ir.service_impersonation import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_fake_api_string(self):
        assert classify_event("fake api endpoint detected") == "fake_api"

    def test_fake_api_dict(self):
        assert classify_event({"action": "rogue api server found"}) == "fake_api"

    def test_identity_spoof(self):
        assert classify_event("service impersonation detected") == "identity_spoof"

    def test_mitm_proxy(self):
        assert classify_event("man in the middle proxy active") == "mitm_proxy"

    def test_name_collision(self):
        assert classify_event("namespace squatting detected") == "name_collision"

    def test_cert_impersonation(self):
        assert classify_event("fake certificate installed") == "cert_impersonation"

    def test_dns_spoof(self):
        assert classify_event("dns poisoning service detected") == "dns_spoof"

    def test_unknown_event(self):
        assert classify_event("normal service request") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("FAKE API ENDPOINT") == "fake_api"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "ssl strip detected"}) == "mitm_proxy"

    def test_spoofed_endpoint(self):
        assert classify_event("spoofed endpoint in cluster") == "fake_api"

    def test_forged_service_header(self):
        assert classify_event("forged service header in request") == "identity_spoof"

    def test_tls_intercept(self):
        assert classify_event("tls intercept proxy found") == "mitm_proxy"

    def test_service_shadowing(self):
        assert classify_event("service shadowing in namespace") == "name_collision"

    def test_certificate_pinning_bypass(self):
        assert classify_event("certificate pinning bypass attempt") == "cert_impersonation"

    def test_dns_rebinding(self):
        assert classify_event("dns rebinding attack vector") == "dns_spoof"

    def test_rogue_ca(self):
        assert classify_event("rogue ca detected in trust store") == "cert_impersonation"

    def test_relay_attack(self):
        assert classify_event("relay attack between services") == "mitm_proxy"

    def test_container_name_spoof(self):
        assert classify_event("container name spoof in registry") == "name_collision"

    def test_dns_takeover(self):
        assert classify_event("dns takeover of service endpoint") == "dns_spoof"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal event"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["fake api endpoint found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["fake_api"] == 1

    def test_multiple_categories(self):
        events = ["fake api", "service impersonation", "dns spoof"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"fake api event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"dns spoof event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["fake api", "normal", "dns spoof", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["service impersonation detected"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "fake api"}, "mitm proxy active", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "certificate forgery detected"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["fake api found"])
        report = format_report(result)
        assert "Service Impersonation" in report

    def test_contains_severity(self):
        result = analyze(["dns spoof detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"fake api event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "fake api"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["dns spoof", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "service impersonation"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has fewer than 5 indicators"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
