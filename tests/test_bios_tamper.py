"""Tests for bios_tamper detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.bios_tamper import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_flash_manipulation_spi(self):
        assert classify_event("spi flash write to bios region") == "flash_manipulation"

    def test_flash_manipulation_flashrom(self):
        assert classify_event({"tool": "flashrom -w malicious.bin"}) == "flash_manipulation"

    def test_flash_manipulation_dump(self):
        assert classify_event("flash chip dump completed") == "flash_manipulation"

    def test_secure_boot_bypass_disable(self):
        assert classify_event("secure boot disable in setup") == "secure_boot_bypass"

    def test_secure_boot_bypass_mok(self):
        assert classify_event({"action": "mok enroll unauthorized key"}) == "secure_boot_bypass"

    def test_secure_boot_bypass_pk(self):
        assert classify_event("pk key replace with attacker key") == "secure_boot_bypass"

    def test_smm_exploitation_handler(self):
        assert classify_event("smm handler install at address") == "smm_exploitation"

    def test_smm_exploitation_ring(self):
        assert classify_event({"detail": "ring -2 access detected"}) == "smm_exploitation"

    def test_nvram_corruption_write(self):
        assert classify_event("nvram write to boot variables") == "nvram_corruption"

    def test_nvram_corruption_efi_var(self):
        assert classify_event({"type": "efi variable modify detected"}) == "nvram_corruption"

    def test_option_rom_injection_pci(self):
        assert classify_event("pci rom modify on device") == "option_rom_injection"

    def test_option_rom_injection_gpu(self):
        assert classify_event({"action": "gpu vbios modify detected"}) == "option_rom_injection"

    def test_tpm_subversion_reset(self):
        assert classify_event("tpm reset attack attempted") == "tpm_subversion"

    def test_tpm_subversion_bus(self):
        assert classify_event({"detail": "tpm bus sniff intercepted"}) == "tpm_subversion"

    def test_unknown_event(self):
        assert classify_event("normal bios health check passed") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("SPI FLASH WRITE to region") == "flash_manipulation"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["routine bios check", "firmware healthy", "boot ok"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["normal", "spi flash write detected", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "flash_manipulation" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "spi flash write malicious",
            "secure boot disable attempt",
            "tpm reset attack found",
            "normal operation",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"nvram write variant {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"flashrom instance {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["spi flash write", "normal", "tpm reset attack", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["smm handler install at 0x1234"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "smm_exploitation"
        assert "smm handler install" in entry["event"]

    def test_dict_events(self):
        events = [{"action": "pci rom modify", "device": "eth0"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "BIOS/UEFI Tampering Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["spi flash write", "secure boot disable", "tpm reset attack"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "flash_manipulation" in report

    def test_report_truncation(self):
        events = [f"flashrom device_{i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and 5 more" in report


class TestLoadEvents:
    def test_load_list(self):
        data = ["event1", "event2"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == data
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        data = {"events": ["a", "b"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a", "b"]
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        data = {"type": "bios event"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == [data]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has fewer than 5 indicators"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
