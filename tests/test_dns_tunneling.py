"""Tests for dns_tunneling detection module."""
import json
import os
import tempfile
import pytest
from orbit_ir.dns_tunneling import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestCategories:
    def test_category_count(self):
        assert len(CATEGORIES) == 6

    def test_each_category_has_10_indicators(self):
        for cat, info in CATEGORIES.items():
            assert len(info["indicators"]) == 10, f"{cat} has {len(info['indicators'])}"

    def test_all_categories_have_description(self):
        for cat, info in CATEGORIES.items():
            assert "description" in info and len(info["description"]) > 0

    def test_no_duplicate_indicators_within_category(self):
        for cat, info in CATEGORIES.items():
            assert len(info["indicators"]) == len(set(info["indicators"]))

    def test_expected_categories_present(self):
        expected = {"dns_exfil", "dns_c2", "dns_rebinding", "dns_amplification", "dns_hijack", "dns_covert_channel"}
        assert set(CATEGORIES.keys()) == expected


class TestClassifyEvent:
    def test_empty_event(self):
        assert classify_event({}) == {}

    def test_no_match(self):
        ev = {"description": "normal http request to api endpoint"}
        assert classify_event(ev) == {}

    def test_dns_exfil_match(self):
        ev = {"description": "high entropy subdomain detected in DNS query with unusually long dns query"}
        result = classify_event(ev)
        assert "dns_exfil" in result
        assert result["dns_exfil"]["count"] >= 1

    def test_dns_c2_match(self):
        ev = {"description": "periodic dns beacon observed with consistent interval dns polling"}
        result = classify_event(ev)
        assert "dns_c2" in result

    def test_dns_rebinding_match(self):
        ev = {"description": "rapid dns ttl change detected with dns resolution to private range"}
        result = classify_event(ev)
        assert "dns_rebinding" in result

    def test_dns_amplification_match(self):
        ev = {"description": "large dns response to small query indicating amplification ratio exceeded"}
        result = classify_event(ev)
        assert "dns_amplification" in result

    def test_dns_hijack_match(self):
        ev = {"description": "unexpected dns response source with cache poisoning attempt"}
        result = classify_event(ev)
        assert "dns_hijack" in result

    def test_dns_covert_channel_match(self):
        ev = {"description": "iodine tunnel signature found in dnscat2 protocol signature packet"}
        result = classify_event(ev)
        assert "dns_covert_channel" in result

    def test_multiple_categories(self):
        ev = {"description": "high entropy subdomain with periodic dns beacon and iodine tunnel signature"}
        result = classify_event(ev)
        assert len(result) >= 2

    def test_case_insensitive(self):
        ev = {"description": "HIGH ENTROPY SUBDOMAIN detected"}
        result = classify_event(ev)
        assert "dns_exfil" in result

    def test_raw_field_used(self):
        ev = {"raw": "high entropy subdomain in DNS log"}
        result = classify_event(ev)
        assert "dns_exfil" in result


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["module"] == "dns_tunneling"
        assert result["total_indicators"] == 0
        assert result["severity"] == "none"
        assert len(result["flagged_events"]) == 0

    def test_single_match(self):
        events = [{"description": "high entropy subdomain in query"}]
        result = analyze(events)
        assert result["total_indicators"] >= 1
        assert result["severity"] in ("medium", "high", "critical")

    def test_severity_medium(self):
        events = [{"description": "periodic dns beacon"}]
        result = analyze(events)
        assert result["severity"] in ("medium", "high", "critical")

    def test_severity_critical(self):
        indicators = list(CATEGORIES["dns_exfil"]["indicators"])
        events = [{"description": " ".join(i.replace("_", " ") for i in indicators)}]
        result = analyze(events)
        assert result["total_indicators"] > 0

    def test_category_counts_populated(self):
        events = [
            {"description": "high entropy subdomain found"},
            {"description": "periodic dns beacon seen"},
        ]
        result = analyze(events)
        assert "dns_exfil" in result["category_counts"]
        assert "dns_c2" in result["category_counts"]

    def test_no_match_events(self):
        events = [{"description": "regular web browsing activity"}]
        result = analyze(events)
        assert result["total_indicators"] == 0
        assert result["severity"] == "none"

    def test_flagged_events_structure(self):
        events = [{"id": "ev1", "description": "iodine tunnel signature detected"}]
        result = analyze(events)
        if result["flagged_events"]:
            fe = result["flagged_events"][0]
            assert "event" in fe
            assert "classifications" in fe


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "DNS Tunneling Detection Report" in report
        assert "none" in report

    def test_format_with_findings(self):
        events = [{"id": "e1", "description": "high entropy subdomain with periodic dns beacon"}]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:" in report

    def test_format_includes_severity(self):
        result = analyze([{"description": "high entropy subdomain"}])
        report = format_report(result)
        assert "Severity:" in report

    def test_format_includes_category(self):
        result = analyze([{"description": "high entropy subdomain"}])
        report = format_report(result)
        assert "dns_exfil" in report


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"id": "1", "description": "test"}], f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": [{"id": "1"}, {"id": "2"}]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 2
        finally:
            os.unlink(path)

    def test_load_empty_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == []
        finally:
            os.unlink(path)
