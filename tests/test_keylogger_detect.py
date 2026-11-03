"""Tests for keylogger behavior detection."""

import json
import pytest
from orbit_ir.keylogger_detect import (
    Detection,
    INPUT_CAPTURE_PATTERNS,
    EXFIL_PATTERNS,
    LOG_FILE_PATTERNS,
    CLIPBOARD_PATTERNS,
    SCREENSHOT_PATTERNS,
    _matches_any,
    _detect_input_hooking,
    _detect_keystroke_logging,
    _detect_clipboard_capture,
    _detect_screenshot_capture,
    _detect_exfiltration,
    analyze_keylogger,
    format_text,
    format_json,
    _load_events,
)


class TestHelpers:
    def test_matches_any_hit(self):
        assert _matches_any("called GetAsyncKeyState", INPUT_CAPTURE_PATTERNS) is not None

    def test_matches_any_miss(self):
        assert _matches_any("normal file write", INPUT_CAPTURE_PATTERNS) is None

    def test_matches_any_case_insensitive(self):
        assert _matches_any("SMTP upload", EXFIL_PATTERNS) == "smtp"

    def test_pattern_sets_not_empty(self):
        assert len(INPUT_CAPTURE_PATTERNS) > 5
        assert len(EXFIL_PATTERNS) > 5
        assert len(LOG_FILE_PATTERNS) > 3
        assert len(CLIPBOARD_PATTERNS) > 3
        assert len(SCREENSHOT_PATTERNS) > 3


class TestInputHooking:
    def test_getasynckeystate(self):
        events = [{"action": "api_call", "target": "GetAsyncKeyState", "agent": "mal"}]
        dets = _detect_input_hooking(events)
        assert len(dets) == 1
        assert dets[0].category == "input_hooking"
        assert dets[0].severity == "critical"

    def test_setwindowshookex(self):
        events = [{"action": "hook", "detail": "SetWindowsHookEx WH_KEYBOARD", "agent": "spy"}]
        dets = _detect_input_hooking(events)
        assert len(dets) == 1

    def test_linux_evdev(self):
        events = [{"action": "open", "target": "/dev/input/event0", "agent": "logger"}]
        dets = _detect_input_hooking(events)
        assert len(dets) == 1

    def test_macos_cgeventtap(self):
        events = [{"action": "call", "detail": "CGEventTapCreate kCGHIDEventTap", "agent": "a"}]
        dets = _detect_input_hooking(events)
        assert len(dets) == 1

    def test_no_match(self):
        events = [{"action": "read", "target": "/etc/passwd", "agent": "a"}]
        assert _detect_input_hooking(events) == []


class TestKeystrokeLogging:
    def test_keylog_write(self):
        events = [{"action": "write", "target": "/tmp/keylog.txt", "agent": "mal"}]
        dets = _detect_keystroke_logging(events)
        assert len(dets) == 1
        assert dets[0].category == "keystroke_logging"

    def test_captured_keys_create(self):
        events = [{"action": "create", "target": "captured_keys.dat", "agent": "spy"}]
        dets = _detect_keystroke_logging(events)
        assert len(dets) == 1

    def test_append_keystroke_log(self):
        events = [{"action": "append", "target": "keystroke_log.bin", "agent": "x"}]
        dets = _detect_keystroke_logging(events)
        assert len(dets) == 1

    def test_read_ignored(self):
        events = [{"action": "read", "target": "/tmp/keylog.txt", "agent": "a"}]
        assert _detect_keystroke_logging(events) == []

    def test_normal_file(self):
        events = [{"action": "write", "target": "report.txt", "agent": "a"}]
        assert _detect_keystroke_logging(events) == []


class TestClipboardCapture:
    def test_getclipboarddata(self):
        events = [{"action": "api_call", "target": "GetClipboardData", "agent": "c"}]
        dets = _detect_clipboard_capture(events)
        assert len(dets) == 1
        assert dets[0].category == "clipboard_capture"
        assert dets[0].severity == "high"

    def test_xclip(self):
        events = [{"action": "exec", "detail": "xclip -o -selection clipboard", "agent": "a"}]
        dets = _detect_clipboard_capture(events)
        assert len(dets) == 1

    def test_no_match(self):
        events = [{"action": "read", "target": "file.txt", "agent": "a"}]
        assert _detect_clipboard_capture(events) == []


class TestScreenshotCapture:
    def test_bitblt(self):
        events = [{"action": "api_call", "target": "BitBlt screen capture", "agent": "s"}]
        dets = _detect_screenshot_capture(events)
        assert len(dets) == 1
        assert dets[0].category == "screenshot_capture"
        assert dets[0].severity == "high"

    def test_scrot(self):
        events = [{"action": "exec", "detail": "scrot /tmp/screen.png", "agent": "a"}]
        dets = _detect_screenshot_capture(events)
        assert len(dets) == 1

    def test_no_match(self):
        events = [{"action": "read", "target": "image.png", "agent": "a"}]
        assert _detect_screenshot_capture(events) == []


class TestExfiltration:
    def test_smtp(self):
        events = [{"action": "send", "detail": "smtp connect to relay.evil.com", "agent": "ex"}]
        dets = _detect_exfiltration(events)
        assert len(dets) == 1
        assert dets[0].category == "exfiltration"
        assert dets[0].severity == "critical"

    def test_discord_webhook(self):
        events = [{"action": "http", "target": "discord_webhook post", "agent": "a"}]
        dets = _detect_exfiltration(events)
        assert len(dets) == 1

    def test_no_match(self):
        events = [{"action": "http", "target": "api.github.com", "agent": "a"}]
        assert _detect_exfiltration(events) == []


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_keylogger([])
        assert r["summary"]["total_detections"] == 0
        assert r["summary"]["overall_severity"] == "none"

    def test_normal_events(self):
        events = [
            {"action": "read", "target": "config.yml", "agent": "app"},
            {"action": "write", "target": "output.log", "agent": "app"},
        ]
        r = analyze_keylogger(events)
        assert r["summary"]["total_detections"] == 0

    def test_full_keylogger_chain(self):
        events = [
            {"action": "hook", "detail": "SetWindowsHookEx WH_KEYBOARD_LL", "agent": "mal"},
            {"action": "write", "target": "/tmp/keylog.txt", "agent": "mal"},
            {"action": "api_call", "target": "GetClipboardData", "agent": "mal"},
            {"action": "api_call", "target": "BitBlt screen capture", "agent": "mal"},
            {"action": "send", "detail": "smtp send to c2.evil.com", "agent": "mal"},
        ]
        r = analyze_keylogger(events)
        assert r["summary"]["total_detections"] == 5
        cats = r["summary"]["by_category"]
        assert "input_hooking" in cats
        assert "keystroke_logging" in cats
        assert "clipboard_capture" in cats
        assert "screenshot_capture" in cats
        assert "exfiltration" in cats
        assert r["summary"]["overall_severity"] == "critical"

    def test_multi_agent(self):
        events = [
            {"action": "hook", "detail": "GetAsyncKeyState", "agent": "a1"},
            {"action": "api_call", "target": "GetClipboardData", "agent": "a2"},
        ]
        r = analyze_keylogger(events)
        assert len(r["summary"]["agents_involved"]) == 2

    def test_high_severity_only(self):
        events = [{"action": "api_call", "target": "GetClipboardData", "agent": "c"}]
        r = analyze_keylogger(events)
        assert r["summary"]["overall_severity"] == "high"


class TestFormat:
    def test_format_text_header(self):
        r = analyze_keylogger([])
        text = format_text(r)
        assert "Keylogger Behavior Detection" in text

    def test_format_text_detections(self):
        events = [{"action": "hook", "detail": "GetAsyncKeyState", "agent": "mal", "timestamp": "T1"}]
        r = analyze_keylogger(events)
        text = format_text(r)
        assert "[CRITICAL]" in text
        assert "mal" in text

    def test_format_json_valid(self):
        events = [{"action": "hook", "detail": "GetAsyncKeyState", "agent": "a"}]
        r = analyze_keylogger(events)
        j = format_json(r)
        parsed = json.loads(j)
        assert "detections" in parsed
        assert "summary" in parsed

    def test_format_text_empty(self):
        r = analyze_keylogger([])
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
