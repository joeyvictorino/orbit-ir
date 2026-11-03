"""Tests for crypto_mining detection module."""
import json
import os
import tempfile
import pytest
from orbit_ir.crypto_mining import (
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
        expected = {"cryptojack_process", "resource_abuse", "pool_connection", "browser_mining", "evasion_technique", "wallet_activity"}
        assert set(CATEGORIES.keys()) == expected


class TestClassifyEvent:
    def test_empty_event(self):
        assert classify_event({}) == {}

    def test_no_match(self):
        ev = {"description": "normal database query executed"}
        assert classify_event(ev) == {}

    def test_cryptojack_match(self):
        ev = {"description": "xmrig binary execution detected with stratum protocol connection"}
        result = classify_event(ev)
        assert "cryptojack_process" in result

    def test_resource_abuse_match(self):
        ev = {"description": "sustained high cpu usage with thermal throttling event"}
        result = classify_event(ev)
        assert "resource_abuse" in result

    def test_pool_connection_match(self):
        ev = {"description": "stratum tcp handshake to mining pool domain resolution"}
        result = classify_event(ev)
        assert "pool_connection" in result

    def test_browser_mining_match(self):
        ev = {"description": "coinhive js inclusion with webassembly mining module"}
        result = classify_event(ev)
        assert "browser_mining" in result

    def test_evasion_match(self):
        ev = {"description": "process name masquerading with cpu throttle on user activity"}
        result = classify_event(ev)
        assert "evasion_technique" in result

    def test_wallet_match(self):
        ev = {"description": "wallet address in config with monero address pattern"}
        result = classify_event(ev)
        assert "wallet_activity" in result

    def test_multiple_categories(self):
        ev = {"description": "xmrig binary execution with stratum tcp handshake and wallet address in config"}
        result = classify_event(ev)
        assert len(result) >= 2

    def test_case_insensitive(self):
        ev = {"description": "XMRIG BINARY EXECUTION detected"}
        result = classify_event(ev)
        assert "cryptojack_process" in result

    def test_raw_field_used(self):
        ev = {"raw": "xmrig binary execution in process list"}
        result = classify_event(ev)
        assert "cryptojack_process" in result


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["module"] == "crypto_mining"
        assert result["total_indicators"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = [{"description": "xmrig binary execution found"}]
        result = analyze(events)
        assert result["total_indicators"] >= 1

    def test_severity_none_for_clean(self):
        result = analyze([{"description": "safe normal activity"}])
        assert result["severity"] == "none"

    def test_category_counts_populated(self):
        events = [
            {"description": "xmrig binary execution"},
            {"description": "stratum tcp handshake"},
        ]
        result = analyze(events)
        total = sum(result["category_counts"].values())
        assert total >= 2

    def test_flagged_events_populated(self):
        events = [{"id": "ev1", "description": "coinhive js inclusion detected"}]
        result = analyze(events)
        assert len(result["flagged_events"]) >= 1

    def test_flagged_event_structure(self):
        events = [{"id": "ev1", "description": "xmrig binary execution observed"}]
        result = analyze(events)
        if result["flagged_events"]:
            fe = result["flagged_events"][0]
            assert "event" in fe
            assert "classifications" in fe


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Crypto Mining Detection Report" in report
        assert "none" in report

    def test_format_with_findings(self):
        events = [{"id": "e1", "description": "xmrig binary execution with stratum tcp handshake"}]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:" in report

    def test_format_includes_severity(self):
        result = analyze([{"description": "sustained high cpu usage"}])
        report = format_report(result)
        assert "Severity:" in report

    def test_format_includes_category(self):
        result = analyze([{"description": "xmrig binary execution"}])
        report = format_report(result)
        assert "cryptojack_process" in report


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

    def test_load_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([], f)
            path = f.name
        try:
            events = load_events(path)
            assert events == []
        finally:
            os.unlink(path)
