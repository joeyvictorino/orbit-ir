"""Tests for dhcp_spoofing detection module."""

import json
import os
import tempfile

from orbit_ir.dhcp_spoofing import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_rogue_server_string(self):
        assert classify_event("rogue dhcp server detected") == "rogue_server"

    def test_rogue_server_dict(self):
        assert classify_event({"alert": "unauthorized dhcp server"}) == "rogue_server"

    def test_starvation(self):
        assert classify_event("dhcp starvation attack in progress") == "starvation"

    def test_spoofed_offer(self):
        assert classify_event("spoofed dhcp offer on subnet") == "spoofed_offer"

    def test_relay_abuse(self):
        assert classify_event("dhcp relay abuse detected") == "relay_abuse"

    def test_option_injection(self):
        assert classify_event("dhcp option injection found") == "option_injection"

    def test_lease_manipulation(self):
        assert classify_event("lease manipulation by rogue agent") == "lease_manipulation"

    def test_unknown_event(self):
        assert classify_event("normal network traffic") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("ROGUE DHCP SERVER FOUND") == "rogue_server"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "address pool exhaustion"}) == "starvation"

    def test_phantom_dhcp(self):
        assert classify_event("phantom dhcp server on vlan") == "rogue_server"

    def test_ip_pool_depletion(self):
        assert classify_event("ip pool depletion attack") == "starvation"

    def test_bogus_dhcp_reply(self):
        assert classify_event("bogus dhcp reply intercepted") == "spoofed_offer"

    def test_option_82_injection(self):
        assert classify_event("option 82 injection via relay") == "relay_abuse"

    def test_gateway_inject(self):
        assert classify_event("gateway inject via dhcp option") == "option_injection"

    def test_dhcp_release_spoof(self):
        assert classify_event("dhcp release spoof targeting client") == "lease_manipulation"

    def test_wpad_injection(self):
        assert classify_event("wpad injection through dhcp") == "option_injection"

    def test_forced_lease_renewal(self):
        assert classify_event("forced lease renewal attack") == "lease_manipulation"

    def test_giaddr_manipulation(self):
        assert classify_event("giaddr manipulation in relay") == "relay_abuse"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal traffic", "another normal event"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["rogue dhcp server found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["rogue_server"] == 1

    def test_multiple_categories(self):
        events = ["rogue dhcp", "dhcp starvation", "spoofed dhcp offer"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"rogue dhcp event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"dhcp starvation event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["rogue dhcp", "normal", "dhcp starvation", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["rogue dhcp server detected"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "rogue dhcp"}, "dhcp relay abuse", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["rogue dhcp found"])
        report = format_report(result)
        assert "DHCP Spoofing" in report

    def test_contains_severity(self):
        result = analyze(["dhcp starvation detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"rogue dhcp event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "rogue dhcp"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["dhcp starvation", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "lease manipulation"}
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
