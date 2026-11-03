"""Tests for bgp_hijack detection module."""

import json
import os
import tempfile

from orbit_ir.bgp_hijack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_prefix_hijack_string(self):
        assert classify_event("prefix hijack detected in routing table") == "prefix_hijack"

    def test_prefix_hijack_dict(self):
        assert classify_event({"alert": "bgp prefix theft from AS12345"}) == "prefix_hijack"

    def test_route_leak(self):
        assert classify_event("bgp route leak to upstream provider") == "route_leak"

    def test_as_path_manipulation(self):
        assert classify_event("as path manipulation in update") == "as_path_manipulation"

    def test_session_hijack(self):
        assert classify_event("bgp session hijack via tcp reset") == "session_hijack"

    def test_rov_bypass(self):
        assert classify_event("rpki bypass for invalid routes") == "rov_bypass"

    def test_community_abuse(self):
        assert classify_event("bgp community abuse in announcement") == "community_abuse"

    def test_unknown_event(self):
        assert classify_event("normal routing update") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("PREFIX HIJACK DETECTED") == "prefix_hijack"

    def test_dict_values_searched(self):
        assert classify_event({"type": "bgp", "detail": "transit leak found"}) == "route_leak"

    def test_stolen_prefix(self):
        assert classify_event("stolen prefix announced by rogue AS") == "prefix_hijack"

    def test_accidental_propagation(self):
        assert classify_event("accidental route propagation to peer") == "route_leak"

    def test_as_path_poison(self):
        assert classify_event("as path poison detected") == "as_path_manipulation"

    def test_bgp_tcp_hijack(self):
        assert classify_event("bgp tcp hijack attempt") == "session_hijack"

    def test_roa_mismatch(self):
        assert classify_event("roa mismatch for prefix") == "rov_bypass"

    def test_blackhole_community_spoof(self):
        assert classify_event("blackhole community spoof from peer") == "community_abuse"

    def test_more_specific_prefix(self):
        assert classify_event("more specific prefix attack") == "prefix_hijack"

    def test_bgp_md5_bypass(self):
        assert classify_event("bgp md5 bypass on session") == "session_hijack"

    def test_route_target_hijack(self):
        assert classify_event("route target hijack in vpn") == "community_abuse"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal update", "keepalive message"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["prefix hijack detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["prefix_hijack"] == 1

    def test_multiple_categories(self):
        events = ["prefix hijack", "route leak", "as path manipulation"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"prefix hijack event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"bgp route leak event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["prefix hijack", "normal", "route leak", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["prefix hijack detected"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "prefix hijack"}, "route leak found", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["normal", "keepalive", "update"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["prefix hijack found"])
        report = format_report(result)
        assert "BGP Hijack" in report

    def test_contains_severity(self):
        result = analyze(["route leak detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"prefix hijack event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "prefix hijack"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["route leak", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "as path manipulation"}
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
