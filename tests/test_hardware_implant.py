"""Tests for hardware_implant detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.hardware_implant import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_rogue_usb_device_unknown(self):
        assert classify_event("unknown usb device connected") == "rogue_usb_device"

    def test_rogue_usb_device_rubber_ducky(self):
        assert classify_event({"alert": "rubber ducky detect on port 3"}) == "rogue_usb_device"

    def test_rogue_usb_device_badusb(self):
        assert classify_event("badusb indicator found on interface") == "rogue_usb_device"

    def test_network_tap_implant_detected(self):
        assert classify_event("network tap detected on segment") == "network_tap_implant"

    def test_network_tap_implant_mirror(self):
        assert classify_event({"type": "mirror port unauthorized on switch"}) == "network_tap_implant"

    def test_network_tap_implant_promiscuous(self):
        assert classify_event("promiscuous nic foreign detected") == "network_tap_implant"

    def test_firmware_backdoor_checksum(self):
        assert classify_event("firmware checksum mismatch on device") == "firmware_backdoor"

    def test_firmware_backdoor_bmc(self):
        assert classify_event({"alert": "bmc unauthorized access detected"}) == "firmware_backdoor"

    def test_firmware_backdoor_option_rom(self):
        assert classify_event("option rom unauthorized in expansion slot") == "firmware_backdoor"

    def test_pci_device_injection_unknown(self):
        assert classify_event("pci device unknown appeared on bus") == "pci_device_injection"

    def test_pci_device_injection_dma(self):
        assert classify_event({"type": "thunderbolt dma attack detected"}) == "pci_device_injection"

    def test_pci_device_injection_iommu(self):
        assert classify_event("iommu bypass attempt from external device") == "pci_device_injection"

    def test_debug_port_exploit_jtag(self):
        assert classify_event("jtag access detected on board") == "debug_port_exploit"

    def test_debug_port_exploit_uart(self):
        assert classify_event({"action": "uart access anomaly on console"}) == "debug_port_exploit"

    def test_debug_port_exploit_swd(self):
        assert classify_event("swd interface active unexpectedly") == "debug_port_exploit"

    def test_hardware_trojan_indicator(self):
        assert classify_event("hardware trojan indicator in analysis") == "hardware_trojan"

    def test_hardware_trojan_power(self):
        assert classify_event({"metric": "power consumption anomaly detected"}) == "hardware_trojan"

    def test_hardware_trojan_counterfeit(self):
        assert classify_event("counterfeit component found in supply") == "hardware_trojan"

    def test_unknown_event(self):
        assert classify_event("normal system operation") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("UNKNOWN USB DEVICE connected") == "rogue_usb_device"


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
        events = ["normal", "unknown usb device connected", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "rogue_usb_device" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "unknown usb device connected",
            "jtag access detected",
            "firmware checksum mismatch",
            "normal event",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"pci device unknown variant {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"unknown usb device instance {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["unknown usb device", "normal", "jtag access detected", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["network tap detected on lan"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "network_tap_implant"
        assert entry["event"] == "network tap detected on lan"

    def test_dict_events(self):
        events = [{"alert": "thunderbolt dma", "source": "pci bus"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Hardware Implant Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["unknown usb device", "jtag access detected", "firmware checksum mismatch"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "rogue_usb_device" in report

    def test_report_truncation(self):
        events = [f"unknown usb device instance {i}" for i in range(15)]
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
