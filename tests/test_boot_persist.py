"""Tests for boot_persist detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.boot_persist import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_bootloader_modification_grub(self):
        assert classify_event("detected grub modify attempt") == "bootloader_modification"

    def test_bootloader_modification_bcdedit(self):
        assert classify_event({"action": "bcdedit /set boot"}) == "bootloader_modification"

    def test_bootloader_modification_efi(self):
        assert classify_event("efi partition write detected") == "bootloader_modification"

    def test_boot_sector_infection_mbr(self):
        assert classify_event("mbr infection found in disk") == "boot_sector_infection"

    def test_boot_sector_infection_raw_disk(self):
        assert classify_event({"type": "raw disk write to sector 0"}) == "boot_sector_infection"

    def test_kernel_module_injection_insmod(self):
        assert classify_event("insmod suspicious.ko loaded") == "kernel_module_injection"

    def test_kernel_module_injection_lkm(self):
        assert classify_event({"cmd": "lkm inject detected"}) == "kernel_module_injection"

    def test_init_system_hijack_systemd(self):
        assert classify_event("systemd unit create persistence.service") == "init_system_hijack"

    def test_init_system_hijack_rc_local(self):
        assert classify_event({"file": "rc.local modify detected"}) == "init_system_hijack"

    def test_scheduled_startup_cron(self):
        assert classify_event("cron reboot job added") == "scheduled_startup"

    def test_scheduled_startup_login_hook(self):
        assert classify_event({"type": "login hook installed"}) == "scheduled_startup"

    def test_firmware_persistence_uefi(self):
        assert classify_event("uefi implant detected in firmware") == "firmware_persistence"

    def test_firmware_persistence_spi(self):
        assert classify_event({"action": "spi flash write to bios region"}) == "firmware_persistence"

    def test_unknown_event(self):
        assert classify_event("normal system operation") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(12345) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("GRUB MODIFY attempt") == "bootloader_modification"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["normal log entry", "routine check", "all clear"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["normal", "grub modify detected", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "bootloader_modification" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "grub modify attempt",
            "insmod rootkit.ko",
            "uefi implant found",
            "normal event",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"mbr infection variant {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"insmod malicious_{i}.ko" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["grub modify", "normal", "insmod bad.ko", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["uefi implant detected"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "firmware_persistence"
        assert entry["event"] == "uefi implant detected"

    def test_dict_events(self):
        events = [{"action": "bcdedit /set", "target": "boot config"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Boot-Level Persistence Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["grub modify", "insmod rootkit.ko", "uefi implant"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "bootloader_modification" in report

    def test_report_truncation(self):
        events = [f"insmod module_{i}.ko" for i in range(15)]
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
        data = {"events": ["a", "b", "c"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            events = load_events(path)
            assert events == ["a", "b", "c"]
        finally:
            os.unlink(path)

    def test_load_single_object(self):
        data = {"type": "single event"}
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
