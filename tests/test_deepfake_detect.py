import pytest
from orbit_ir.deepfake_detect import classify_event, analyze, format_report, CATEGORIES


class TestClassifyEvent:
    def test_voice_synthesis(self):
        ev = {"action": "voice clone detected in call"}
        assert "voice_synthesis" in classify_event(ev)

    def test_image_manipulation(self):
        ev = {"action": "face swap detected in uploaded photo"}
        assert "image_manipulation" in classify_event(ev)

    def test_video_deepfake(self):
        ev = {"action": "deepfake video identified in stream"}
        assert "video_deepfake" in classify_event(ev)

    def test_text_generation(self):
        ev = {"action": "ai generated text in email body"}
        assert "text_generation" in classify_event(ev)

    def test_identity_impersonation(self):
        ev = {"action": "synthetic identity used for access"}
        assert "identity_impersonation" in classify_event(ev)

    def test_no_match(self):
        ev = {"action": "normal file upload"}
        assert classify_event(ev) == []

    def test_multiple_categories(self):
        ev = {"action": "voice clone used for impersonation attack"}
        cats = classify_event(ev)
        assert "voice_synthesis" in cats
        assert "identity_impersonation" in cats


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["summary"]["total_events"] == 0
        assert result["summary"]["flagged_events"] == 0
        assert result["summary"]["risk_level"] == "low"

    def test_single_event(self):
        events = [{"action": "face swap in video conference"}]
        result = analyze(events)
        assert result["summary"]["flagged_events"] == 1
        assert "image_manipulation" in result["categories"]

    def test_no_flags(self):
        events = [{"action": "normal"}, {"action": "standard operation"}]
        result = analyze(events)
        assert result["summary"]["flagged_events"] == 0

    def test_risk_medium(self):
        events = [
            {"action": "voice clone"},
            *[{"action": "normal"} for _ in range(5)],
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "medium"

    def test_risk_high(self):
        events = [
            {"action": "face swap"},
            {"action": "deepfake video"},
            *[{"action": "normal"} for _ in range(3)],
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "high"

    def test_risk_critical(self):
        events = [
            {"action": "voice clone"},
            {"action": "face swap"},
            {"action": "deepfake video"},
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "critical"

    def test_category_event_tracking(self):
        events = [
            {"action": "face swap detected"},
            {"action": "another face swap found"},
        ]
        result = analyze(events)
        assert result["categories"]["image_manipulation"]["count"] == 2
        assert len(result["categories"]["image_manipulation"]["events"]) == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Total events: 0" in report
        assert "Deepfake Detection" in report

    def test_with_findings(self):
        events = [{"action": "voice clone attack detected"}]
        result = analyze(events)
        report = format_report(result)
        assert "voice_synthesis" in report
        assert "Flagged: 1" in report


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"{cat} has no patterns"

    def test_category_names(self):
        expected = {"voice_synthesis", "image_manipulation", "video_deepfake",
                    "text_generation", "identity_impersonation"}
        assert set(CATEGORIES.keys()) == expected
