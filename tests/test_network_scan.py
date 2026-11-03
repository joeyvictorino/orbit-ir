"""Tests for network scan detection module."""

import json
import os
import tempfile

from orbit_ir.network_scan import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_port_scan(self):
        assert classify_event("port scan detected on target") == "port_scan"

    def test_service_enumeration(self):
        assert classify_event("service enumeration on web server") == "service_enumeration"

    def test_arp_scan(self):
        assert classify_event("arp scan across subnet") == "arp_scan"

    def test_icmp_sweep(self):
        assert classify_event("icmp sweep of network range") == "icmp_sweep"

    def test_traceroute(self):
        assert classify_event("traceroute to external host") == "traceroute"

    def test_dns_enumeration(self):
        assert classify_event("dns enumeration of target domain") == "dns_enumeration"

    def test_smb_enumeration(self):
        assert classify_event("smb enumeration on windows host") == "smb_enumeration"

    def test_snmp_scan(self):
        assert classify_event("snmp scan with default community string") == "snmp_scan"

    def test_unknown(self):
        assert classify_event("normal network traffic") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "syn scan detected"}) == "port_scan"

    def test_case_insensitive(self):
        assert classify_event("PORT SCAN on host") == "port_scan"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_banner_grab(self):
        assert classify_event("banner grabbing on open ports") == "service_enumeration"

    def test_zone_transfer(self):
        assert classify_event("zone transfer attempt on ns1") == "dns_enumeration"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_single_match(self):
        result = analyze(["port scan detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_severity_high(self):
        events = [f"port scan {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"syn scan {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_no_matches(self):
        result = analyze(["normal traffic", "http request", "dns response"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_category_counts(self):
        events = ["port scan detected", "arp scan found", "port scan again"]
        result = analyze(events)
        assert result["category_counts"]["port_scan"] == 2
        assert result["category_counts"]["arp_scan"] == 1

    def test_detection_rate(self):
        events = ["syn scan", "normal", "arp scan", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["snmp scan detected"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "snmp_scan"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Network Scan Detection Report" in text
        assert "none" in text

    def test_format_with_findings(self):
        result = analyze(["port scan detected", "arp scan found"])
        text = format_report(result)
        assert "port_scan" in text
        assert "arp_scan" in text

    def test_format_truncation(self):
        events = [f"syn scan {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["scan1", "scan2"], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["scan1", "scan2"]
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
            json.dump({"type": "scan"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [{"type": "scan"}]
        finally:
            os.unlink(path)
