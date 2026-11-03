"""Tests for code signing bypass detection module."""
import pytest
from orbit_ir.code_signing_bypass import (
    analyze_code_signing,
    format_text,
    format_json,
)


def test_empty_events():
    r = analyze_code_signing([])
    assert r["summary"]["total"] == 0
    assert r["summary"]["agents_affected"] == 0


def test_no_detections_benign():
    events = [
        {"agent": "a1", "action": "read_file", "path": "/tmp/data.txt"},
        {"agent": "a1", "command": "ls -la"},
    ]
    r = analyze_code_signing(events)
    assert r["summary"]["total"] == 0


def test_signing_disable_bypass():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "signing_disabled" for d in r["detections"])


def test_signing_disable_unrestricted():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Unrestricted"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "signing_disabled" for d in r["detections"])


def test_signing_disable_powershell_ep():
    events = [
        {"agent": "a1", "command": "powershell -ep bypass -file script.ps1"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "signing_disabled" for d in r["detections"])


def test_cert_tampering_certutil():
    events = [
        {"agent": "a1", "command": "certutil -addstore root cert.cer"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "cert_tampering" for d in r["detections"])


def test_cert_tampering_self_signed():
    events = [
        {"agent": "a1", "action": "create self-signed certificate"},
    ]
    r = analyze_code_signing(events)
    cats = [d for d in r["detections"] if d["category"] == "cert_tampering"]
    assert len(cats) >= 1
    assert cats[0]["severity"] == "critical"


def test_cert_tampering_makecert():
    events = [
        {"agent": "a1", "tool": "makecert to generate test cert"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "cert_tampering" for d in r["detections"])


def test_integrity_bypass_bcdedit():
    events = [
        {"agent": "a1", "command": "bcdedit /set testsigning on"},
    ]
    r = analyze_code_signing(events)
    cats = {d["category"] for d in r["detections"]}
    assert "integrity_bypass" in cats


def test_integrity_bypass_disable_driver_signing():
    events = [
        {"agent": "a1", "action": "disable driver signing enforcement"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "integrity_bypass" for d in r["detections"])


def test_integrity_bypass_nointegritychecks():
    events = [
        {"agent": "a1", "command": "bcdedit /set nointegritychecks ON"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "integrity_bypass" for d in r["detections"])


def test_unsigned_execution():
    events = [
        {"agent": "a1", "output": "WARNING: unsigned binary executed", "path": "C:\\temp\\evil.exe"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "unsigned_execution" for d in r["detections"])


def test_unsigned_invalid_signature():
    events = [
        {"agent": "a1", "error": "invalid signature on module.dll", "file": "module.dll"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "unsigned_execution" for d in r["detections"])


def test_unsigned_certificate_expired():
    events = [
        {"agent": "a1", "error": "certificate expired for driver.sys"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "unsigned_execution" for d in r["detections"])


def test_applocker_bypass():
    events = [
        {"agent": "a1", "action": "bypass applocker policy restriction"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "applocker_bypass" for d in r["detections"])


def test_applocker_wdac_bypass():
    events = [
        {"agent": "a1", "action": "circumvent WDAC code integrity enforcement"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "applocker_bypass" for d in r["detections"])


def test_applocker_no_bypass_keyword():
    events = [
        {"agent": "a1", "action": "check applocker policy status"},
    ]
    r = analyze_code_signing(events)
    assert not any(d["category"] == "applocker_bypass" for d in r["detections"])


def test_dll_sideloading():
    events = [
        {"agent": "a1", "action": "dll sideload attack via search order hijack"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "dll_sideloading" for d in r["detections"])


def test_dll_sideloading_phantom():
    events = [
        {"agent": "a1", "description": "phantom dll placed in application directory"},
    ]
    r = analyze_code_signing(events)
    assert any(d["category"] == "dll_sideloading" for d in r["detections"])


def test_multiple_agents():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass"},
        {"agent": "a2", "action": "disable driver signing enforcement"},
    ]
    r = analyze_code_signing(events)
    assert r["summary"]["agents_affected"] == 2


def test_severity_critical():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass"},
    ]
    r = analyze_code_signing(events)
    assert r["summary"]["max_severity"] == "critical"


def test_severity_high_unsigned():
    events = [
        {"agent": "a1", "output": "unsigned binary loaded"},
    ]
    r = analyze_code_signing(events)
    has_high = any(d["severity"] == "high" for d in r["detections"])
    assert has_high


def test_by_category_counts():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass"},
        {"agent": "a1", "command": "powershell -ep bypass -file a.ps1"},
    ]
    r = analyze_code_signing(events)
    assert r["summary"]["by_category"].get("signing_disabled", 0) >= 2


def test_timestamp_preserved():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass", "timestamp": "2024-03-01T12:00:00Z"},
    ]
    r = analyze_code_signing(events)
    assert r["detections"][0]["timestamp"] == "2024-03-01T12:00:00Z"


def test_format_text_header():
    events = [{"agent": "a1", "command": "Set-ExecutionPolicy Bypass"}]
    r = analyze_code_signing(events)
    text = format_text(r)
    assert "Code Signing Bypass" in text
    assert "CRITICAL" in text


def test_format_text_empty():
    r = analyze_code_signing([])
    text = format_text(r)
    assert "Total detections: 0" in text


def test_format_json_valid():
    events = [{"agent": "a1", "command": "Set-ExecutionPolicy Bypass"}]
    r = analyze_code_signing(events)
    import json
    parsed = json.loads(format_json(r))
    assert "detections" in parsed
    assert "summary" in parsed


def test_unknown_agent():
    events = [{"agent": "unknown", "command": "Set-ExecutionPolicy Bypass"}]
    r = analyze_code_signing(events)
    assert r["detections"][0]["agent"] == "unknown"


def test_combined_attack_chain():
    events = [
        {"agent": "a1", "command": "Set-ExecutionPolicy Bypass"},
        {"agent": "a1", "action": "create self-signed certificate for code signing"},
        {"agent": "a1", "command": "bcdedit /set nointegritychecks ON"},
        {"agent": "a1", "output": "unsigned binary executed"},
    ]
    r = analyze_code_signing(events)
    assert r["summary"]["total"] >= 4
    assert r["summary"]["max_severity"] == "critical"
    cats = {d["category"] for d in r["detections"]}
    assert "signing_disabled" in cats
    assert "cert_tampering" in cats
    assert "integrity_bypass" in cats
    assert "unsigned_execution" in cats
