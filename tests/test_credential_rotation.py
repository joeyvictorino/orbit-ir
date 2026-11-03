"""Tests for credential_rotation detection module."""
import json
import os
import tempfile
import pytest
from orbit_ir.credential_rotation import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_stale_credential(self):
        m = classify_event({"msg": "credential not rotated for 90 days"})
        assert "stale_credential" in m

    def test_rotation_failure(self):
        m = classify_event({"msg": "rotation failed during key renewal"})
        assert "rotation_failure" in m

    def test_shared_credential(self):
        m = classify_event({"msg": "credential shared across multiple services"})
        assert "shared_credential" in m

    def test_weak_credential(self):
        m = classify_event({"msg": "weak key strength detected in api token"})
        assert "weak_credential" in m

    def test_emergency_rotation(self):
        m = classify_event({"msg": "emergency rotation triggered after breach"})
        assert "emergency_rotation" in m

    def test_rotation_gap(self):
        m = classify_event({"msg": "rotation window gap detected in schedule"})
        assert "rotation_gap" in m

    def test_no_match(self):
        m = classify_event({"msg": "normal operation completed"})
        assert len(m) == 0

    def test_string_event(self):
        m = classify_event("credential not rotated")
        assert "stale_credential" in m

    def test_multiple_categories(self):
        m = classify_event({"msg": "credential not rotated and rotation failed"})
        assert "stale_credential" in m
        assert "rotation_failure" in m

    def test_case_insensitive(self):
        m = classify_event({"msg": "CREDENTIAL NOT ROTATED"})
        assert "stale_credential" in m

    def test_empty_event(self):
        m = classify_event({})
        assert len(m) == 0


class TestAnalyze:
    def test_empty_events(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_events"] == 0

    def test_single_match(self):
        r = analyze([{"msg": "expired api key found"}])
        assert r["flagged_events"] == 1
        assert r["category_totals"]["stale_credential"] > 0

    def test_no_matches(self):
        r = analyze([{"msg": "all clear"}])
        assert r["flagged_events"] == 0

    def test_multiple_events(self):
        events = [
            {"msg": "credential not rotated"},
            {"msg": "rotation failed"},
            {"msg": "normal event"},
        ]
        r = analyze(events)
        assert r["total_events"] == 3
        assert r["flagged_events"] == 2

    def test_category_totals(self):
        events = [
            {"msg": "credential not rotated"},
            {"msg": "credential not rotated again static credential in use"},
        ]
        r = analyze(events)
        assert r["category_totals"]["stale_credential"] >= 2

    def test_all_categories_initialized(self):
        r = analyze([])
        for cat in CATEGORIES:
            assert cat in r["category_totals"]

    def test_results_structure(self):
        r = analyze([{"msg": "rotation failed"}])
        assert len(r["results"]) == 1
        assert "event" in r["results"][0]
        assert "matches" in r["results"][0]

    def test_many_events(self):
        events = [{"msg": f"event {i}"} for i in range(100)]
        events[50] = {"msg": "credential not rotated"}
        r = analyze(events)
        assert r["total_events"] == 100
        assert r["flagged_events"] == 1

    def test_mixed_types(self):
        events = [{"msg": "rotation failed"}, "expired api key"]
        r = analyze(events)
        assert r["flagged_events"] == 2


class TestFormatReport:
    def test_report_header(self):
        r = analyze([])
        report = format_report(r)
        assert "Credential Rotation Detection Report" in report

    def test_report_totals(self):
        r = analyze([{"msg": "rotation failed"}])
        report = format_report(r)
        assert "Flagged events: 1" in report

    def test_report_categories(self):
        r = analyze([{"msg": "rotation failed"}])
        report = format_report(r)
        assert "rotation_failure" in report

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
