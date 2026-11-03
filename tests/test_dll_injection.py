"""Tests for DLL injection detection module."""
import pytest
from orbit_ir.dll_injection import (
    analyze_dll_injection,
    format_text,
    format_json,
)


def test_empty_events():
    r = analyze_dll_injection([])
    assert r["summary"]["total"] == 0
    assert r["summary"]["agents_affected"] == 0


def test_no_detections_benign():
    events = [
        {"agent": "a1", "action": "read_file", "path": "/tmp/data.txt"},
        {"agent": "a1", "action": "write_file", "path": "/tmp/output.csv"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["total"] == 0


def test_api_injection_virtualalloc():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "target": "1234"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["total"] >= 1
    cats = {d["category"] for d in r["detections"]}
    assert "api_injection" in cats


def test_api_injection_createremotethread():
    events = [
        {"agent": "a1", "api_call": "CreateRemoteThread", "target": "pid:5678"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "api_injection" for d in r["detections"])


def test_api_injection_writeprocessmemory():
    events = [
        {"agent": "a1", "function": "WriteProcessMemory", "target": "0x1000"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "api_injection" for d in r["detections"])


def test_suspicious_dll_load():
    events = [
        {"agent": "a1", "action": "LoadLibrary", "module": "ntdll.dll"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "suspicious_dll_load" for d in r["detections"])


def test_suspicious_dll_ws2():
    events = [
        {"agent": "a1", "action": "dll load", "path": "C:\\Windows\\ws2_32.dll"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "suspicious_dll_load" for d in r["detections"])


def test_benign_dll_no_detection():
    events = [
        {"agent": "a1", "action": "dll load", "module": "myapp.dll"},
    ]
    r = analyze_dll_injection(events)
    assert not any(d["category"] == "suspicious_dll_load" for d in r["detections"])


def test_process_hollowing():
    events = [
        {"agent": "a1", "action": "NtUnmapViewOfSection", "target": "explorer.exe"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "process_hollowing" for d in r["detections"])


def test_process_hollowing_runpe():
    events = [
        {"agent": "a1", "description": "RunPE injection technique detected"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "process_hollowing" for d in r["detections"])


def test_reflective_injection():
    events = [
        {"agent": "a1", "action": "reflective LoadLibrary GetProcAddress injection"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "reflective_injection" for d in r["detections"])


def test_reflective_single_keyword_no_detect():
    events = [
        {"agent": "a1", "action": "reflective comment in code"},
    ]
    r = analyze_dll_injection(events)
    assert not any(d["category"] == "reflective_injection" for d in r["detections"])


def test_target_process_svchost():
    events = [
        {"agent": "a1", "action": "inject code", "target": "svchost.exe"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "target_process_injection" for d in r["detections"])


def test_target_process_lsass():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "process": "lsass.exe"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "target_process_injection" for d in r["detections"])


def test_shellcode_detected():
    events = [
        {"agent": "a1", "action": "execute shellcode payload", "details": "staged payload delivery"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "shellcode_detected" for d in r["detections"])


def test_shellcode_nop_sled():
    events = [
        {"agent": "a1", "description": "nop sled detected in memory region"},
    ]
    r = analyze_dll_injection(events)
    assert any(d["category"] == "shellcode_detected" for d in r["detections"])


def test_multiple_agents():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "target": "1234"},
        {"agent": "a2", "action": "CreateRemoteThread", "target": "5678"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["agents_affected"] == 2


def test_severity_critical():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "target": "1234"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["max_severity"] == "critical"


def test_severity_high_for_dll_load():
    events = [
        {"agent": "a1", "action": "LoadLibrary dll", "module": "kernel32.dll"},
    ]
    r = analyze_dll_injection(events)
    has_high = any(d["severity"] == "high" for d in r["detections"])
    assert has_high


def test_by_category_counts():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "target": "1"},
        {"agent": "a1", "api_call": "CreateRemoteThread", "target": "2"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["by_category"].get("api_injection", 0) >= 2


def test_timestamp_preserved():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "timestamp": "2024-01-15T10:00:00Z"},
    ]
    r = analyze_dll_injection(events)
    assert r["detections"][0]["timestamp"] == "2024-01-15T10:00:00Z"


def test_format_text_header():
    events = [{"agent": "a1", "action": "VirtualAllocEx"}]
    r = analyze_dll_injection(events)
    text = format_text(r)
    assert "DLL/Process Injection" in text
    assert "CRITICAL" in text


def test_format_text_empty():
    r = analyze_dll_injection([])
    text = format_text(r)
    assert "Total detections: 0" in text


def test_format_json_valid():
    events = [{"agent": "a1", "action": "VirtualAllocEx"}]
    r = analyze_dll_injection(events)
    import json
    parsed = json.loads(format_json(r))
    assert "detections" in parsed
    assert "summary" in parsed


def test_unknown_agent():
    events = [{"agent": "unknown", "action": "VirtualAllocEx"}]
    r = analyze_dll_injection(events)
    assert r["summary"]["total"] >= 1
    assert r["detections"][0]["agent"] == "unknown"


def test_combined_attack_chain():
    events = [
        {"agent": "a1", "action": "VirtualAllocEx", "target": "pid:100"},
        {"agent": "a1", "function": "WriteProcessMemory", "target": "0x4000"},
        {"agent": "a1", "api_call": "CreateRemoteThread", "process": "svchost.exe"},
    ]
    r = analyze_dll_injection(events)
    assert r["summary"]["total"] >= 3
    assert r["summary"]["max_severity"] == "critical"
