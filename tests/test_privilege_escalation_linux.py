"""Tests for the Linux privilege escalation detection module."""

import pytest

from orbit_ir.privilege_escalation_linux import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_suid_abuse(self):
        assert classify_event("Found suid binary owned by root") == "suid_abuse"

    def test_kernel_exploit(self):
        assert classify_event("Attempted dirty cow kernel exploit on host") == "kernel_exploit"

    def test_sudo_abuse(self):
        assert classify_event("Detected sudo misconfiguration allowing root") == "sudo_abuse"

    def test_cron_manipulation(self):
        assert classify_event("Attacker modified writable cron script") == "cron_manipulation"

    def test_container_escape(self):
        assert classify_event("Container escape via docker socket abuse") == "container_escape"

    def test_capability_abuse(self):
        assert classify_event("Exploited cap_sys_admin exploit for root access") == "capability_abuse"

    def test_unknown(self):
        assert classify_event("Normal user login from office") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "suid binary exploitation"}) == "suid_abuse"

    def test_case_insensitive(self):
        assert classify_event("KERNEL EXPLOIT detected") == "kernel_exploit"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"

    def test_dirty_pipe(self):
        assert classify_event("CVE-2022-0847 dirty pipe kernel vulnerability") == "kernel_exploit"

    def test_crontab_hijack(self):
        assert classify_event("crontab hijack by low-privilege user") == "cron_manipulation"

    def test_kubernetes_escape(self):
        assert classify_event("kubernetes pod escape via hostpath mount") == "container_escape"

    def test_gtfobins(self):
        assert classify_event("used gtfobins suid technique to escalate") == "suid_abuse"


class TestAnalyze:
    def test_empty(self):
        r = analyze([])
        assert r["total_events"] == 0
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"
        assert r["detection_rate"] == 0.0

    def test_single_match(self):
        r = analyze(["found suid binary in /usr/bin"])
        assert r["flagged_count"] == 1
        assert r["severity"] == "medium"

    def test_no_matches(self):
        r = analyze(["normal login event", "user opened a file"])
        assert r["flagged_count"] == 0
        assert r["severity"] == "none"

    def test_severity_high(self):
        events = [f"suid binary variant {i}" for i in range(6)]
        r = analyze(events)
        assert r["severity"] == "high"

    def test_severity_critical(self):
        events = [f"suid binary variant {i}" for i in range(11)]
        r = analyze(events)
        assert r["severity"] == "critical"

    def test_category_counts(self):
        events = [
            "suid binary found",
            "kernel exploit attempted",
            "another suid binary",
        ]
        r = analyze(events)
        assert r["category_counts"]["suid_abuse"] == 2
        assert r["category_counts"]["kernel_exploit"] == 1

    def test_detection_rate(self):
        events = ["suid binary found", "normal event", "kernel exploit", "normal event 2"]
        r = analyze(events)
        assert r["detection_rate"] == pytest.approx(0.5)

    def test_flagged_structure(self):
        r = analyze(["sudo misconfiguration found"])
        assert r["flagged_events"][0]["category"] == "sudo_abuse"
        assert r["flagged_events"][0]["index"] == 0


class TestFormatReport:
    def test_format_empty(self):
        r = analyze([])
        text = format_report(r)
        assert "Linux Privilege Escalation" in text
        assert "0" in text

    def test_format_with_findings(self):
        r = analyze(["suid binary exploitation", "kernel exploit attempt"])
        text = format_report(r)
        assert "suid_abuse" in text
        assert "kernel_exploit" in text

    def test_format_truncation(self):
        events = [f"suid binary variant number {i}" for i in range(15)]
        r = analyze(events)
        text = format_report(r)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        r = analyze(["suid binary found", "normal event"])
        text = format_report(r)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('["suid binary found", "kernel exploit"]')
        events = load_events(str(p))
        assert len(events) == 2

    def test_load_dict_with_events_key(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('{"events": ["suid binary found"]}')
        events = load_events(str(p))
        assert len(events) == 1

    def test_load_single_dict(self, tmp_path):
        p = tmp_path / "events.json"
        p.write_text('{"action": "suid binary exploitation"}')
        events = load_events(str(p))
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"{cat} has no patterns"

    def test_category_names(self):
        expected = {
            "suid_abuse", "kernel_exploit", "sudo_abuse",
            "cron_manipulation", "container_escape", "capability_abuse",
        }
        assert set(CATEGORIES.keys()) == expected
