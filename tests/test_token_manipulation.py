"""Tests for token_manipulation detection module."""

import json
import os
import tempfile

from orbit_ir.token_manipulation import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_token_forge_string(self):
        assert classify_event("forged auth token detected") == "token_forge"

    def test_token_forge_dict(self):
        assert classify_event({"action": "counterfeit token created"}) == "token_forge"

    def test_token_replay(self):
        assert classify_event("replayed auth token in request") == "token_replay"

    def test_token_escalation(self):
        assert classify_event("token escalation to admin role") == "token_escalation"

    def test_session_fixation(self):
        assert classify_event("session fixation attack detected") == "session_fixation"

    def test_oauth_abuse(self):
        assert classify_event("oauth redirect manipulation found") == "oauth_abuse"

    def test_jwt_tamper(self):
        assert classify_event("jwt signature bypass attempt") == "jwt_tamper"

    def test_unknown_event(self):
        assert classify_event("normal auth request") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("TOKEN FORGE DETECTED") == "token_forge"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "jwt none algorithm used"}) == "jwt_tamper"

    def test_synthetic_token(self):
        assert classify_event("synthetic token generation attempt") == "token_forge"

    def test_stale_token_replay(self):
        assert classify_event("stale token replay from cache") == "token_replay"

    def test_scope_expansion(self):
        assert classify_event("scope expansion attack on api") == "token_escalation"

    def test_session_pinning(self):
        assert classify_event("session pinning attack on login") == "session_fixation"

    def test_refresh_token_theft(self):
        assert classify_event("refresh token theft via redirect") == "oauth_abuse"

    def test_jwt_algorithm_confusion(self):
        assert classify_event("jwt algorithm confusion exploit") == "jwt_tamper"

    def test_token_fabrication(self):
        assert classify_event("token fabrication by rogue agent") == "token_forge"

    def test_credential_replay(self):
        assert classify_event("credential replay attack detected") == "token_replay"

    def test_session_id_planting(self):
        assert classify_event("session id planting via url") == "session_fixation"

    def test_jwt_kid_injection(self):
        assert classify_event("jwt kid injection in header") == "jwt_tamper"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal event"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["forged auth token found"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["token_forge"] == 1

    def test_multiple_categories(self):
        events = ["token forge", "token replay", "jwt tamper"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"token forge event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"jwt tamper event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["token forge", "normal", "jwt tamper", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["session fixation detected"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "token forge"}, "oauth abuse detected", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "jwt claim modification found"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["token forge found"])
        report = format_report(result)
        assert "Token Manipulation" in report

    def test_contains_severity(self):
        result = analyze(["jwt tamper detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"token forge event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "token forge"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["jwt tamper", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "oauth abuse"}
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
