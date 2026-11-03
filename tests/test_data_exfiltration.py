"""Tests for the data exfiltration detection module."""

import pytest

from orbit_ir.data_exfiltration import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_network_exfil(self):
        assert classify_event("large upload detected to external IP") == "network_exfil"

    def test_cloud_storage_exfil(self):
        assert classify_event("s3 bucket upload unauthorized by user") == "cloud_storage_exfil"

    def test_email_exfil(self):
        assert classify_event("email exfiltration of customer database") == "email_exfil"

    def test_physical_exfil(self):
        assert classify_event("usb data copy of sensitive files") == "physical_exfil"

    def test_steganography_exfil(self):
        assert classify_event("steganography exfil detected in PNG") == "steganography_exfil"

    def test_dns_exfil(self):
        assert classify_event("dns exfiltration via txt records") == "dns_exfil"

    def test_unknown(self):
        assert classify_event("normal file access on share drive") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "large upload detected"}) == "network_exfil"

    def test_case_insensitive(self):
        assert classify_event("DNS EXFILTRATION via covert channel") == "dns_exfil"

    def test_non_string_non_dict(self):
        assert classify_event(99) == "unknown"

    def test_dropbox(self):
        assert classify_event("dropbox upload suspicious files") == "cloud_storage_exfil"

    def test_bcc_exfil(self):
        assert classify_event("bcc exfiltration to external address") == "email_exfil"

    def test_bluetooth(self):
        assert classify_event("bluetooth file transfer of restricted docs") == "physical_exfil"

    def test_lsb_encoding(self):
        assert classify_event("lsb encoding detected in uploaded images") == "steganography_exfil"

    def test_base64_dns(self):
        assert classify_event("base64 dns query with encoded payload") == "dns_exfil"


class TestAnalyze:
    def test_empty(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"
        assert r["detection_rate"] == 0.0

    def test_single_match(self):
        r = analyze(["large upload detected to external server"])
        assert r["flagged_count"] == 1
        assert r["severity"] == "medium"

    def test_no_matches(self):
        r = analyze(["normal login event", "routine backup completed"])
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"

    def test_severity_high(self):
        events = [f"large upload detected variant {i}" for i in range(6)]
        r = analyze(events)
        assert r["severity"] == "high"

    def test_severity_critical(self):
        events = [f"large upload detected variant {i}" for i in range(11)]
        r = analyze(events)
        assert r["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "large upload detected externally",
            "dns exfiltration attempt",
            "another large upload detected",
        ]
        r = analyze(events)
        assert r["category_counts"]["network_exfil"] == 2
        assert r["category_counts"]["dns_exfil"] == 1

    def test_detection_rate(self):
        events = ["large upload detected", "normal event", "dns exfiltration", "normal event 2"]
        r = analyze(events)
        assert r["detection_rate"] == pytest.approx(0.5)

    def test_flagged_structure(self):
        r = analyze(["email exfiltration detected"])
        assert r["flagged_events"][0]["category"] == "email_exfil"
        assert r["flagged_events"][0]["index"] == 0


class TestFormatReport:
    def test_format_empty(self):
        r = analyze([])
        text = format_report(r)
        assert "Data Exfiltration" in text
        assert "0" in text

    def test_format_with_findings(self):
        r = analyze(["large upload detected", "dns exfiltration attempt"])
        text = format_report(r)
        assert "network_exfil" in text
        assert "dns_exfil" in text

    def test_format_truncation(self):
        events = [f"large upload detected variant {i}" for i in range(15)]
        r = analyze(events)
        text = format_report(r)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        r = analyze(["large upload detected", "normal event"])
        text = format_report(r)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('["large upload detected", "dns exfiltration"]')
        events = load_events(str(p))
        assert len(events) == 2

    def test_load_dict_with_events_key(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('{"events": ["large upload detected"]}')
        events = load_events(str(p))
        assert len(events) == 1

    def test_load_single_dict(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('{"action": "email exfiltration detected"}')
        events = load_events(str(p))
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"{cat} has no patterns"

    def test_category_names(self):
        expected = {
            "network_exfil", "cloud_storage_exfil", "email_exfil",
            "physical_exfil", "steganography_exfil", "dns_exfil",
        }
        assert set(CATEGORIES.keys()) == expected
