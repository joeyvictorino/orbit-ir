"""Tests for vm_escape detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.vm_escape import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_hypervisor_exploit_vmm(self):
        assert classify_event("vmm vulnerability found in host") == "hypervisor_exploit"

    def test_hypervisor_exploit_hypercall(self):
        assert classify_event({"action": "hypercall abuse detected"}) == "hypervisor_exploit"

    def test_hypervisor_exploit_kvm(self):
        assert classify_event("kvm exploit triggered from guest") == "hypervisor_exploit"

    def test_vm_host_pivot_breakout(self):
        assert classify_event("vm breakout attempt detected") == "vm_host_pivot"

    def test_vm_host_pivot_host_filesystem(self):
        assert classify_event({"type": "host filesystem access from guest"}) == "vm_host_pivot"

    def test_vm_host_pivot_hypervisor_shell(self):
        assert classify_event("hypervisor shell obtained via escape") == "vm_host_pivot"

    def test_shared_resource_abuse_clipboard(self):
        assert classify_event("clipboard escape attempt detected") == "shared_resource_abuse"

    def test_shared_resource_abuse_vmtools(self):
        assert classify_event({"cmd": "vmtools exploit triggered"}) == "shared_resource_abuse"

    def test_shared_resource_abuse_guest_additions(self):
        assert classify_event("guest additions vuln exploited") == "shared_resource_abuse"

    def test_virtual_device_attack_virtio(self):
        assert classify_event("virtio exploit in network driver") == "virtual_device_attack"

    def test_virtual_device_attack_vfio(self):
        assert classify_event({"action": "vfio attack on passthrough device"}) == "virtual_device_attack"

    def test_virtual_device_attack_gpu(self):
        assert classify_event("virtual gpu escape via shader bug") == "virtual_device_attack"

    def test_memory_mapping_exploit_dma(self):
        assert classify_event("dma attack vm memory region") == "memory_mapping_exploit"

    def test_memory_mapping_exploit_iommu(self):
        assert classify_event({"type": "iommu bypass achieved"}) == "memory_mapping_exploit"

    def test_memory_mapping_exploit_ept(self):
        assert classify_event("ept violation exploited for read") == "memory_mapping_exploit"

    def test_guest_host_channel_vmci(self):
        assert classify_event("vmci exploit on communication channel") == "guest_host_channel"

    def test_guest_host_channel_vsock(self):
        assert classify_event({"action": "vsock escape via buffer overflow"}) == "guest_host_channel"

    def test_guest_host_channel_backdoor(self):
        assert classify_event("vmware backdoor port accessed") == "guest_host_channel"

    def test_unknown_event(self):
        assert classify_event("normal vm operation logged") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(42) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("HYPERVISOR EXPLOIT in progress") == "hypervisor_exploit"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["routine vm log", "normal guest operation", "heartbeat ok"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["normal", "kvm exploit detected", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "hypervisor_exploit" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "vmm vulnerability found",
            "clipboard escape attempt",
            "dma attack vm detected",
            "normal event",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"vm breakout variant {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"kvm exploit attempt {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["kvm exploit", "normal", "vsock escape", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["vmci exploit detected"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "guest_host_channel"
        assert entry["event"] == "vmci exploit detected"

    def test_dict_events(self):
        events = [{"action": "hypercall abuse", "target": "host kernel"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "VM Escape Attempt Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["kvm exploit", "clipboard escape", "vmci exploit"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "hypervisor_exploit" in report

    def test_report_truncation(self):
        events = [f"vm breakout attempt {i}" for i in range(15)]
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
