"""Tests for vpn_tunnel_abuse detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.vpn_tunnel_abuse import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_unauthorized_vpn_rogue(self):
        assert classify_event("rogue vpn client detected on host") == "unauthorized_vpn"

    def test_unauthorized_vpn_policy(self):
        assert classify_event({"action": "vpn policy violation flagged"}) == "unauthorized_vpn"

    def test_unauthorized_vpn_shadow(self):
        assert classify_event("shadow vpn connection established") == "unauthorized_vpn"

    def test_split_tunnel_exploit_abuse(self):
        assert classify_event("split tunneling abuse detected") == "split_tunnel_exploit"

    def test_split_tunnel_exploit_route(self):
        assert classify_event({"type": "tunnel route manipulation observed"}) == "split_tunnel_exploit"

    def test_split_tunnel_exploit_bypass(self):
        assert classify_event("split tunnel bypass active") == "split_tunnel_exploit"

    def test_vpn_credential_theft_stolen(self):
        assert classify_event("vpn password stolen from cache") == "vpn_credential_theft"

    def test_vpn_credential_theft_dump(self):
        assert classify_event({"status": "vpn credential dump completed"}) == "vpn_credential_theft"

    def test_vpn_credential_theft_hijack(self):
        assert classify_event("vpn session hijack in progress") == "vpn_credential_theft"

    def test_tunnel_encapsulation_nested(self):
        assert classify_event("nested tunnel detected on network") == "tunnel_encapsulation"

    def test_tunnel_encapsulation_gre(self):
        assert classify_event({"protocol": "gre tunnel abuse found"}) == "tunnel_encapsulation"

    def test_tunnel_encapsulation_wireguard(self):
        assert classify_event("wireguard abuse for covert channel") == "tunnel_encapsulation"

    def test_vpn_exfiltration_smuggling(self):
        assert classify_event("vpn data smuggling detected") == "vpn_exfiltration"

    def test_vpn_exfiltration_bulk(self):
        assert classify_event({"method": "bulk vpn upload in progress"}) == "vpn_exfiltration"

    def test_vpn_exfiltration_covert(self):
        assert classify_event("vpn covert channel active") == "vpn_exfiltration"

    def test_vpn_pivot_lateral(self):
        assert classify_event("vpn lateral movement detected") == "vpn_pivot"

    def test_vpn_pivot_bridge(self):
        assert classify_event({"result": "vpn bridge attack observed"}) == "vpn_pivot"

    def test_vpn_pivot_expansion(self):
        assert classify_event("vpn access expansion across segments") == "vpn_pivot"

    def test_unknown_event(self):
        assert classify_event("normal network activity logged") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("ROGUE VPN detected") == "unauthorized_vpn"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0
        assert result["severity"] == "none"

    def test_no_matches(self):
        events = ["normal traffic", "routine connection", "standard access"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["rogue vpn detected on endpoint"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_medium_severity(self):
        events = ["rogue vpn", "vpn password stolen", "normal"] * 2
        result = analyze(events)
        assert result["flagged_count"] > 0
        assert result["severity"] in ("medium", "high")

    def test_high_severity(self):
        events = [f"rogue vpn instance {i}" for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"rogue vpn instance {i}" for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "rogue vpn detected",
            "split tunneling abuse found",
            "vpn credential dump completed",
        ]
        result = analyze(events)
        assert "unauthorized_vpn" in result["category_counts"]
        assert "split_tunnel_exploit" in result["category_counts"]
        assert "vpn_credential_theft" in result["category_counts"]

    def test_detection_rate(self):
        events = ["rogue vpn", "normal", "normal", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.25

    def test_flagged_event_structure(self):
        events = ["vpn lateral movement detected"]
        result = analyze(events)
        flagged = result["flagged_events"][0]
        assert "index" in flagged
        assert "category" in flagged
        assert "event" in flagged

    def test_dict_events(self):
        events = [{"action": "rogue vpn", "target": "endpoint01"}]
        result = analyze(events)
        assert result["flagged_count"] == 1

    def test_mixed_events(self):
        events = [
            "rogue vpn detected",
            {"action": "vpn data smuggling"},
            "normal event",
            42,
        ]
        result = analyze(events)
        assert result["flagged_count"] == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "VPN Tunnel Abuse" in report
        assert "0" in report

    def test_report_with_findings(self):
        events = ["rogue vpn detected", "vpn credential dump found"]
        result = analyze(events)
        report = format_report(result)
        assert "unauthorized_vpn" in report
        assert "vpn_credential_theft" in report

    def test_report_truncation(self):
        events = [f"rogue vpn variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report

    def test_severity_in_report(self):
        events = ["vpn lateral movement"]
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
            json.dump({"action": "rogue vpn"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "unauthorized_vpn", "split_tunnel_exploit", "vpn_credential_theft",
            "tunnel_encapsulation", "vpn_exfiltration", "vpn_pivot",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_each_category_has_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
