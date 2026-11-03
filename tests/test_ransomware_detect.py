"""Tests for ransomware behavior detection."""
import json
import pytest
from orbit_ir.ransomware_detect import (
    analyze_ransomware, format_text, format_json, _load_events,
    _is_file_event, _has_ransom_extension, _is_ransom_note,
    _is_shadow_delete, RANSOM_EXTENSIONS, RANSOM_NOTE_PATTERNS,
)


class TestHelpers:
    def test_is_file_event_write(self):
        assert _is_file_event({"action": "file_write"})

    def test_is_file_event_create(self):
        assert _is_file_event({"tool": "create_file"})

    def test_is_file_event_false(self):
        assert not _is_file_event({"action": "network_request"})

    def test_has_ransom_extension(self):
        assert _has_ransom_extension({"path": "/data/report.encrypted"})

    def test_has_ransom_extension_false(self):
        assert not _has_ransom_extension({"path": "/data/report.pdf"})

    def test_is_ransom_note(self):
        assert _is_ransom_note({"file": "/tmp/DECRYPT.txt"})

    def test_is_ransom_note_false(self):
        assert not _is_ransom_note({"file": "/tmp/report.pdf"})

    def test_is_shadow_delete(self):
        assert _is_shadow_delete({"command": "vssadmin delete shadows /all"})

    def test_is_shadow_delete_bcdedit(self):
        assert _is_shadow_delete({"command": "bcdedit /set {default} recoveryenabled No"})

    def test_is_shadow_delete_false(self):
        assert not _is_shadow_delete({"command": "ls -la"})

    def test_ransom_extensions_exist(self):
        assert len(RANSOM_EXTENSIONS) > 10

    def test_ransom_note_patterns_exist(self):
        assert len(RANSOM_NOTE_PATTERNS) > 5


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_ransomware([])
        assert r["summary"]["total"] == 0

    def test_normal_events_no_detection(self):
        events = [{"agent": "a1", "action": "read_file", "path": "/data/report.pdf"}]
        r = analyze_ransomware(events)
        assert r["summary"]["total"] == 0

    def test_mass_encryption(self):
        events = [
            {"agent": "a1", "action": "file_write", "path": f"/data/file{i}.encrypted"}
            for i in range(10)
        ]
        r = analyze_ransomware(events)
        cats = [d["category"] for d in r["detections"]]
        assert "mass_encryption" in cats

    def test_ransom_note_creation(self):
        events = [
            {"agent": "a1", "action": "file_write", "file": "/tmp/DECRYPT.txt"},
        ]
        r = analyze_ransomware(events)
        cats = [d["category"] for d in r["detections"]]
        assert "ransom_note" in cats

    def test_shadow_deletion(self):
        events = [
            {"agent": "a1", "command": "vssadmin delete shadows /all /quiet"},
        ]
        r = analyze_ransomware(events)
        cats = [d["category"] for d in r["detections"]]
        assert "shadow_delete" in cats

    def test_c2_beacon_after_encrypt(self):
        events = [
            {"agent": "a1", "action": "file_write", "path": "/data/x.encrypted", "timestamp": "2024-01-01T00:00:00"},
            {"agent": "a1", "action": "http_request", "url": "http://evil.com/key", "timestamp": "2024-01-01T00:05:00"},
        ]
        r = analyze_ransomware(events)
        cats = [d["category"] for d in r["detections"]]
        assert "c2_beacon" in cats

    def test_severity_critical(self):
        events = [
            {"agent": "a1", "action": "file_write", "path": f"/data/file{i}.encrypted"}
            for i in range(10)
        ]
        r = analyze_ransomware(events)
        assert r["summary"]["max_severity"] == "critical"

    def test_multi_agent(self):
        events = [
            {"agent": "a1", "action": "file_write", "path": f"/data/a{i}.encrypted"} for i in range(6)
        ] + [
            {"agent": "a2", "action": "file_write", "path": f"/data/b{i}.locked"} for i in range(6)
        ]
        r = analyze_ransomware(events)
        assert r["summary"]["agents_affected"] == 2

    def test_by_category_counts(self):
        events = [
            {"agent": "a1", "action": "file_write", "file": "/tmp/DECRYPT.txt"},
            {"agent": "a1", "command": "vssadmin delete shadows /all"},
        ]
        r = analyze_ransomware(events)
        assert r["summary"]["by_category"].get("ransom_note", 0) >= 1
        assert r["summary"]["by_category"].get("shadow_delete", 0) >= 1


class TestFormat:
    def test_format_text_header(self):
        r = analyze_ransomware([])
        text = format_text(r)
        assert "Ransomware" in text

    def test_format_text_detections(self):
        events = [{"agent": "a1", "action": "file_write", "file": "/tmp/DECRYPT.txt"}]
        r = analyze_ransomware(events)
        text = format_text(r)
        assert "ransom_note" in text

    def test_format_json_valid(self):
        r = analyze_ransomware([])
        j = format_json(r)
        parsed = json.loads(j)
        assert "detections" in parsed

    def test_format_text_empty(self):
        r = analyze_ransomware([])
        text = format_text(r)
        assert "0" in text


class TestLoadEvents:
    def test_load_list(self):
        assert _load_events([{"a": 1}]) == [{"a": 1}]

    def test_load_dict_with_events(self):
        assert _load_events({"events": [{"a": 1}]}) == [{"a": 1}]

    def test_load_single_dict(self):
        assert _load_events({"a": 1}) == [{"a": 1}]

    def test_load_other(self):
        assert _load_events("string") == []
