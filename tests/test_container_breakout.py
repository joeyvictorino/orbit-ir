"""Tests for container_breakout detection module."""

import json
import os
import tempfile
import pytest

from orbit_ir.container_breakout import (
    CATEGORIES,
    classify_event,
    analyze,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_namespace_manipulation_nsenter(self):
        assert classify_event("nsenter host namespace detected") == "namespace_manipulation"

    def test_namespace_manipulation_unshare(self):
        assert classify_event({"action": "unshare exploit attempt"}) == "namespace_manipulation"

    def test_namespace_manipulation_pid(self):
        assert classify_event("pid namespace break from container") == "namespace_manipulation"

    def test_cgroup_escape_release_agent(self):
        assert classify_event("release_agent abuse detected") == "cgroup_escape"

    def test_cgroup_escape_writable(self):
        assert classify_event({"type": "cgroup writable path found"}) == "cgroup_escape"

    def test_cgroup_escape_v1(self):
        assert classify_event("cgroup v1 exploit triggered") == "cgroup_escape"

    def test_mount_abuse_docker_sock(self):
        assert classify_event("docker.sock mount detected in container") == "mount_abuse"

    def test_mount_abuse_procfs(self):
        assert classify_event({"cmd": "procfs escape via /proc/1"}) == "mount_abuse"

    def test_mount_abuse_hostpath(self):
        assert classify_event("hostpath volume abuse in pod") == "mount_abuse"

    def test_privileged_exploit_sys_admin(self):
        assert classify_event("cap_sys_admin exploit in container") == "privileged_exploit"

    def test_privileged_exploit_seccomp(self):
        assert classify_event({"action": "seccomp bypass achieved"}) == "privileged_exploit"

    def test_privileged_exploit_apparmor(self):
        assert classify_event("apparmor disable from container") == "privileged_exploit"

    def test_kernel_vuln_exploit_dirty_cow(self):
        assert classify_event("dirty cow container escape attempt") == "kernel_vuln_exploit"

    def test_kernel_vuln_exploit_runc(self):
        assert classify_event({"type": "runc vulnerability exploited"}) == "kernel_vuln_exploit"

    def test_kernel_vuln_exploit_io_uring(self):
        assert classify_event("io_uring escape from container") == "kernel_vuln_exploit"

    def test_runtime_attack_docker_api(self):
        assert classify_event("docker api unauth access detected") == "runtime_attack"

    def test_runtime_attack_containerd(self):
        assert classify_event({"action": "containerd exploit via grpc"}) == "runtime_attack"

    def test_runtime_attack_podman(self):
        assert classify_event("podman escape attempt logged") == "runtime_attack"

    def test_unknown_event(self):
        assert classify_event("normal container operation") == "unknown"

    def test_unknown_numeric(self):
        assert classify_event(99) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_empty_dict(self):
        assert classify_event({}) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("DOCKER.SOCK MOUNT detected") == "mount_abuse"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_no_matches(self):
        events = ["container started", "health check ok", "pod running"]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        events = ["normal", "docker.sock mount found", "normal"]
        result = analyze(events)
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert "mount_abuse" in result["category_counts"]

    def test_multiple_categories(self):
        events = [
            "namespace escape detected",
            "cgroup escape attempt",
            "docker api unauth found",
            "normal event",
        ]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"cgroup escape variant {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"docker.sock mount attempt {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["nsenter host", "normal", "runc vulnerability", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_event_structure(self):
        events = ["cap_sys_admin exploit detected"]
        result = analyze(events)
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "privileged_exploit"
        assert entry["event"] == "cap_sys_admin exploit detected"

    def test_dict_events(self):
        events = [{"action": "release_agent abuse", "target": "host"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Container Breakout Detection Report" in report
        assert "Flagged events:        0" in report

    def test_report_with_findings(self):
        events = ["namespace escape", "cgroup escape", "docker api unauth"]
        result = analyze(events)
        report = format_report(result)
        assert "Category Breakdown:" in report
        assert "Flagged Events" in report
        assert "namespace_manipulation" in report

    def test_report_truncation(self):
        events = [f"namespace escape attempt {i}" for i in range(15)]
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
