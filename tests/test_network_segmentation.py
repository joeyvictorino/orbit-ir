"""Tests for network_segmentation detection module."""
import json
import os
import tempfile
import pytest
from orbit_ir.network_segmentation import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_cross_zone_access(self):
        m = classify_event({"msg": "cross-zone connection detected from DMZ"})
        assert "cross_zone_access" in m

    def test_flat_network(self):
        m = classify_event({"msg": "flat network topology detected in scan"})
        assert "flat_network" in m

    def test_firewall_bypass(self):
        m = classify_event({"msg": "firewall rule bypassed via exception"})
        assert "firewall_bypass" in m

    def test_vlan_hopping(self):
        m = classify_event({"msg": "vlan hopping detected on trunk port"})
        assert "vlan_hopping" in m

    def test_microseg_violation(self):
        m = classify_event({"msg": "microsegmentation violated between pods"})
        assert "microseg_violation" in m

    def test_routing_abuse(self):
        m = classify_event({"msg": "route injection detected in routing table"})
        assert "routing_abuse" in m

    def test_no_match(self):
        m = classify_event({"msg": "normal traffic observed"})
        assert len(m) == 0

    def test_string_event(self):
        m = classify_event("cross-zone connection from web to db")
        assert "cross_zone_access" in m

    def test_multiple_categories(self):
        m = classify_event({"msg": "cross-zone connection and vlan hopping detected"})
        assert "cross_zone_access" in m
        assert "vlan_hopping" in m

    def test_case_insensitive(self):
        m = classify_event({"msg": "FLAT NETWORK TOPOLOGY"})
        assert "flat_network" in m

    def test_empty_event(self):
        m = classify_event({})
        assert len(m) == 0


class TestAnalyze:
    def test_empty_events(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_events"] == 0

    def test_single_match(self):
        r = analyze([{"msg": "firewall rule bypassed"}])
        assert r["flagged_events"] == 1
        assert r["category_totals"]["firewall_bypass"] > 0

    def test_no_matches(self):
        r = analyze([{"msg": "all clear"}])
        assert r["flagged_events"] == 0

    def test_multiple_events(self):
        events = [
            {"msg": "cross-zone connection"},
            {"msg": "vlan hopping detected"},
            {"msg": "normal event"},
        ]
        r = analyze(events)
        assert r["total_events"] == 3
        assert r["flagged_events"] == 2

    def test_category_totals(self):
        events = [
            {"msg": "cross-zone connection detected"},
            {"msg": "zone boundary crossed again inter-zone traffic"},
        ]
        r = analyze(events)
        assert r["category_totals"]["cross_zone_access"] >= 2

    def test_all_categories_initialized(self):
        r = analyze([])
        for cat in CATEGORIES:
            assert cat in r["category_totals"]

    def test_results_structure(self):
        r = analyze([{"msg": "vlan hopping detected"}])
        assert len(r["results"]) == 1
        assert "event" in r["results"][0]
        assert "matches" in r["results"][0]

    def test_many_events(self):
        events = [{"msg": f"event {i}"} for i in range(100)]
        events[50] = {"msg": "flat network topology"}
        r = analyze(events)
        assert r["total_events"] == 100
        assert r["flagged_events"] == 1

    def test_mixed_types(self):
        events = [{"msg": "route injection detected"}, "bgp hijack event"]
        r = analyze(events)
        assert r["flagged_events"] == 2


class TestFormatReport:
    def test_report_header(self):
        r = analyze([])
        report = format_report(r)
        assert "Network Segmentation Detection Report" in report

    def test_report_totals(self):
        r = analyze([{"msg": "vlan hopping detected"}])
        report = format_report(r)
        assert "Flagged events: 1" in report

    def test_report_categories(self):
        r = analyze([{"msg": "firewall rule bypassed"}])
        report = format_report(r)
        assert "firewall_bypass" in report

    def test_empty_report(self):
        r = analyze([])
        report = format_report(r)
        assert "Flagged events: 0" in report


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"a": 1}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1

    def test_load_dict_with_events(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": [{"a": 1}, {"b": 2}]}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"msg": "test"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_phrases(self):
        for cat, phrases in CATEGORIES.items():
            assert len(phrases) == 10, f"{cat} has {len(phrases)} phrases"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
