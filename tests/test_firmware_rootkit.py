import pytest
from orbit_ir.firmware_rootkit import classify_event, analyze, format_report, CATEGORIES


class TestClassifyEvent:
    def test_firmware_modification(self):
        ev = {"action": "firmware flash detected on device"}
        assert "firmware_modification" in classify_event(ev)

    def test_boot_persistence(self):
        ev = {"action": "bootkit installed in MBR"}
        assert "boot_persistence" in classify_event(ev)

    def test_hardware_implant(self):
        ev = {"action": "BMC backdoor connection established"}
        assert "hardware_implant" in classify_event(ev)

    def test_driver_rootkit(self):
        ev = {"action": "unsigned driver loaded into kernel"}
        assert "driver_rootkit" in classify_event(ev)

    def test_secure_boot_bypass(self):
        ev = {"action": "secure boot disable via UEFI variable"}
        assert "secure_boot_bypass" in classify_event(ev)

    def test_no_match(self):
        ev = {"action": "normal user login"}
        assert classify_event(ev) == []

    def test_multiple_categories(self):
        ev = {"action": "firmware flash with unsigned driver injection"}
        cats = classify_event(ev)
        assert "firmware_modification" in cats
        assert "driver_rootkit" in cats


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["summary"]["total_events"] == 0
        assert result["summary"]["flagged_events"] == 0
        assert result["summary"]["risk_level"] == "low"

    def test_single_event(self):
        events = [{"action": "firmware flash on server"}]
        result = analyze(events)
        assert result["summary"]["flagged_events"] == 1
        assert "firmware_modification" in result["categories"]

    def test_no_flags(self):
        events = [{"action": "normal operation"}, {"action": "user login"}]
        result = analyze(events)
        assert result["summary"]["flagged_events"] == 0
        assert result["summary"]["risk_level"] == "low"

    def test_risk_medium(self):
        events = [
            {"action": "firmware flash"},
            *[{"action": "normal"} for _ in range(5)],
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "medium"

    def test_risk_high(self):
        events = [
            {"action": "firmware flash"},
            {"action": "bootkit detected"},
            *[{"action": "normal"} for _ in range(3)],
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "high"

    def test_risk_critical(self):
        events = [
            {"action": "firmware flash"},
            {"action": "bootkit detected"},
            {"action": "unsigned driver loaded"},
        ]
        result = analyze(events)
        assert result["summary"]["risk_level"] == "critical"

    def test_category_counts(self):
        events = [
            {"action": "firmware flash"},
            {"action": "firmware flash on another device"},
        ]
        result = analyze(events)
        assert result["categories"]["firmware_modification"]["count"] == 2


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Total events: 0" in report
        assert "Firmware Rootkit" in report

    def test_with_findings(self):
        events = [{"action": "bootkit installed in MBR"}]
        result = analyze(events)
        report = format_report(result)
        assert "boot_persistence" in report
        assert "Flagged: 1" in report


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"{cat} has no patterns"

    def test_category_names(self):
        expected = {"firmware_modification", "boot_persistence", "hardware_implant",
                    "driver_rootkit", "secure_boot_bypass"}
        assert set(CATEGORIES.keys()) == expected
