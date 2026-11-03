"""Tests for typosquat_detect detection module."""

import json
import os
import tempfile

from orbit_ir.typosquat_detect import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_homoglyph_domain(self):
        assert classify_event("homoglyph domain registered for target") == "homoglyph_substitution"

    def test_homoglyph_idn(self):
        assert classify_event({"action": "idn homograph attack detected"}) == "homoglyph_substitution"

    def test_homoglyph_cyrillic(self):
        assert classify_event("cyrillic substitution in domain name") == "homoglyph_substitution"

    def test_transposition_typo(self):
        assert classify_event("transposition domain gogle.com registered") == "transposition_typo"

    def test_transposition_adjacent_key(self):
        assert classify_event({"type": "keyboard adjacent key typo detected"}) == "transposition_typo"

    def test_transposition_misspelled(self):
        assert classify_event("misspelled domain registered for phishing") == "transposition_typo"

    def test_missing_character(self):
        assert classify_event("missing character domain googe.com") == "missing_character"

    def test_missing_character_omitted(self):
        assert classify_event({"detail": "omitted letter in brand domain"}) == "missing_character"

    def test_added_character(self):
        assert classify_event("extra character domain googgle.com") == "added_character"

    def test_added_character_doubled(self):
        assert classify_event({"type": "doubled letter domain registered"}) == "added_character"

    def test_subdomain_impersonation(self):
        assert classify_event("subdomain impersonation login.google.evil.com") == "subdomain_impersonation"

    def test_subdomain_fake(self):
        assert classify_event({"action": "fake subdomain created for phishing"}) == "subdomain_impersonation"

    def test_combosquatting(self):
        assert classify_event("combosquat domain google-login.com") == "combosquatting"

    def test_combosquatting_brand_login(self):
        assert classify_event({"url": "brand-login domain registered"}) == "combosquatting"

    def test_unknown_event(self):
        assert classify_event("normal DNS resolution for legitimate domain") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_single_flagged(self):
        events = ["homoglyph domain attack detected"]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["homoglyph_substitution"] == 1

    def test_no_flags(self):
        events = ["normal web traffic", "dns resolution ok"]
        result = analyze(events)
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_high_severity(self):
        events = [
            "homoglyph domain found",
            "transposition domain detected",
            "missing character domain seen",
            "extra character domain registered",
            "subdomain impersonation detected",
            "combosquat domain found",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 6
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"homoglyph domain variant {i}" for i in range(12)]
        result = analyze(events)
        assert result["flagged_count"] == 12
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["homoglyph domain found", "normal event", "transposition domain detected", "safe traffic"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_mixed_categories(self):
        events = [
            {"action": "cyrillic substitution detected"},
            {"action": "keyboard adjacent key typo"},
            {"action": "combosquat domain registered"},
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Typosquatting Detection Report" in report
        assert "Total events analyzed: 0" in report

    def test_format_with_findings(self):
        events = ["homoglyph domain found", "transposition domain detected"]
        result = analyze(events)
        report = format_report(result)
        assert "Flagged events:        2" in report
        assert "Category Breakdown:" in report

    def test_format_truncation(self):
        events = [f"homoglyph domain variant {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report


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
            json.dump({"events": [{"type": "test"}]}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "single"}, f)
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 1
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_present(self):
        expected = {
            "homoglyph_substitution", "transposition_typo",
            "missing_character", "added_character",
            "subdomain_impersonation", "combosquatting",
        }
        assert set(CATEGORIES.keys()) == expected

    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has too few indicators"
