"""Tests for usb_attack detection module."""

import json
import os
import tempfile

from orbit_ir.usb_attack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


def _ev(msg, agent="agent-1", **kw):
    d = {"message": msg, "agent_id": agent, "timestamp": "2025-01-01T00:00:00Z"}
    d.update(kw)
    return d


# ---- classify per category ----

def test_classify_usb_device_spoofing():
    ev = _ev("HID emulation attack detected on USB port")
    r = classify_event(ev)
    assert "usb_device_spoofing" in r["indicators"]
    assert r["confidence"] > 0


def test_classify_usb_spoofing_badusb():
    ev = _ev("BadUSB payload deployed via modified firmware")
    r = classify_event(ev)
    assert "usb_device_spoofing" in r["indicators"]


def test_classify_usb_spoofing_ducky():
    ev = _ev("Rubber Ducky keystroke injection detected")
    r = classify_event(ev)
    assert "usb_device_spoofing" in r["indicators"]


def test_classify_usb_spoofing_hid():
    ev = _ev("HID attack payload injected via USB gadget")
    r = classify_event(ev)
    assert "usb_device_spoofing" in r["indicators"]


def test_classify_autorun_exploitation():
    ev = _ev("autorun.inf created on removable drive E:")
    r = classify_event(ev)
    assert "autorun_exploitation" in r["indicators"]


def test_classify_autorun_autoplay():
    ev = _ev("autoplay exploit triggered on USB insertion")
    r = classify_event(ev)
    assert "autorun_exploitation" in r["indicators"]


def test_classify_firmware_tampering():
    ev = _ev("USB firmware modification detected on controller")
    r = classify_event(ev)
    assert "firmware_tampering" in r["indicators"]


def test_classify_firmware_reflash():
    ev = _ev("USB firmware modification and controller reprogramming detected")
    r = classify_event(ev)
    assert "firmware_tampering" in r["indicators"]


def test_classify_data_exfiltration_usb():
    ev = _ev("steal data to USB drive via agent exfiltration")
    r = classify_event(ev)
    assert "data_exfiltration_usb" in r["indicators"]


def test_classify_exfil_dead_drop():
    ev = _ev("USB dead drop exfiltration point established")
    r = classify_event(ev)
    assert "data_exfiltration_usb" in r["indicators"]


def test_classify_usb_boot_attack():
    ev = _ev("USB boot attack persistence implant backdoor deployed")
    r = classify_event(ev)
    assert "usb_boot_attack" in r["indicators"]


def test_classify_boot_live_usb():
    ev = _ev("live USB persistence implant backdoor installed")
    r = classify_event(ev)
    assert "usb_boot_attack" in r["indicators"]


def test_classify_charging_attack():
    ev = _ev("juice jacking detected at public charging station")
    r = classify_event(ev)
    assert "charging_attack" in r["indicators"]


def test_classify_charging_malicious():
    ev = _ev("malicious charging station data intercept detected")
    r = classify_event(ev)
    assert "charging_attack" in r["indicators"]


def test_classify_no_match():
    ev = _ev("normal device plugged in and working fine")
    r = classify_event(ev)
    assert r["category"] == ""
    assert r["confidence"] == 0
    assert r["indicators"] == []


# ---- analyze ----

def test_analyze_empty():
    r = analyze([])
    assert r["total_events"] == 0
    assert r["usb_attack_events"] == 0
    assert r["risk_score"] == 0
    assert r["risk_level"] == "none"
    assert r["agents_involved"] == []
    assert r["attack_chains"] == []


def test_analyze_single():
    evts = [_ev("HID emulation attack on USB port with BadUSB")]
    r = analyze(evts)
    assert r["total_events"] == 1
    assert r["usb_attack_events"] == 1
    assert r["risk_score"] > 0


def test_analyze_mixed():
    evts = [
        _ev("HID emulation spoofing detected on USB", agent="a1"),
        _ev("autorun.inf created on removable drive", agent="a1"),
        _ev("USB firmware modification on controller chip", agent="a2"),
        _ev("mass data copy to USB flash drive exfiltration", agent="a2"),
        _ev("USB boot attack persistence implant backdoor", agent="a3"),
        _ev("normal USB activity no attack", agent="a4"),
    ]
    r = analyze(evts)
    assert r["total_events"] == 6
    assert r["usb_attack_events"] == 5
    assert r["risk_level"] in ("medium", "high", "critical")

    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["usb_device_spoofing"] >= 1
    assert cats["autorun_exploitation"] >= 1
    assert cats["firmware_tampering"] >= 1
    assert cats["data_exfiltration_usb"] >= 1
    assert cats["usb_boot_attack"] >= 1


def test_analyze_agents():
    evts = [
        _ev("BadUSB attack deployed", agent="usb-bot-1"),
        _ev("autorun.inf exploit created", agent="usb-bot-2"),
    ]
    r = analyze(evts)
    assert sorted(r["agents_involved"]) == ["usb-bot-1", "usb-bot-2"]


# ---- chain detection ----

def test_chain_detection():
    evts = [
        _ev("HID emulation spoofing on USB port", agent="a1"),
        _ev("autorun.inf abuse on removable", agent="a1"),
        _ev("mass data exfiltration to USB drive", agent="a1"),
    ]
    r = analyze(evts)
    assert len(r["attack_chains"]) >= 1
    chain = r["attack_chains"][0]
    assert chain["agent"] == "a1"
    assert len(chain["steps"]) >= 2
    assert chain["chain_score"] > 0


def test_chain_multiple_agents():
    evts = [
        _ev("BadUSB payload deployed", agent="a1"),
        _ev("autorun.inf exploit triggered", agent="a1"),
        _ev("USB firmware modification on controller chip", agent="a2"),
        _ev("USB boot attack persistence implant backdoor", agent="a2"),
    ]
    r = analyze(evts)
    agents = [c["agent"] for c in r["attack_chains"]]
    assert "a1" in agents
    assert "a2" in agents


def test_chain_single_event_no_chain():
    evts = [_ev("BadUSB deployed", agent="solo")]
    r = analyze(evts)
    chains_for_solo = [c for c in r["attack_chains"] if c["agent"] == "solo"]
    assert len(chains_for_solo) == 0


# ---- format_report ----

def test_format_report_empty():
    r = analyze([])
    text = format_report(r)
    assert "USB Attack Analysis" in text
    assert "Total events: 0" in text
    assert "Risk score: 0.00" in text


def test_format_report_with_data():
    evts = [
        _ev("BadUSB payload on HID device", agent="a1"),
        _ev("autorun.inf created exploit", agent="a1"),
        _ev("USB firmware tamper modification", agent="a2"),
    ]
    r = analyze(evts)
    text = format_report(r)
    assert "USB Attack Analysis" in text
    assert "usb_device_spoofing" in text
    assert "Attack chains:" in text


def test_format_report_categories():
    evts = [
        _ev("mass data copy exfiltration to USB flash"),
        _ev("juice jacking at charging station"),
        _ev("live USB boot persistence implant"),
    ]
    r = analyze(evts)
    text = format_report(r)
    assert "events" in text
    assert "severity=" in text


# ---- load_events ----

def test_load_events_missing():
    r = load_events("/nonexistent/path/xyz")
    assert r == []


def test_load_events_file():
    evts = [_ev("BadUSB attack detected")]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(evts, f)
        f.flush()
        loaded = load_events(f.name)
    os.unlink(f.name)
    assert len(loaded) == 1
    assert "BadUSB" in loaded[0]["message"]


def test_load_events_single_dict():
    ev = _ev("autorun exploit created")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(ev, f)
        f.flush()
        loaded = load_events(f.name)
    os.unlink(f.name)
    assert len(loaded) == 1


def test_load_events_directory():
    with tempfile.TemporaryDirectory() as d:
        for i in range(3):
            p = os.path.join(d, f"events_{i}.json")
            with open(p, "w") as f:
                json.dump([_ev(f"usb event {i}")], f)
        loaded = load_events(d)
    assert len(loaded) == 3


# ---- CATEGORIES structure ----

def test_categories_structure():
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 2
        assert info["severity"] in ("critical", "high", "medium", "low")


def test_all_categories_present():
    expected = {
        "usb_device_spoofing", "autorun_exploitation", "firmware_tampering",
        "data_exfiltration_usb", "usb_boot_attack", "charging_attack",
    }
    assert set(CATEGORIES.keys()) == expected


# ---- risk levels ----

def test_risk_level_none():
    r = analyze([_ev("normal USB device activity")])
    assert r["risk_level"] == "none"


def test_risk_level_scales():
    few = analyze([
        _ev("BadUSB HID emulation attack"),
        _ev("normal safe device plugged in"),
        _ev("another normal USB event logged"),
        _ev("benign device connection noticed"),
    ])
    many = analyze([
        _ev("BadUSB HID emulation attack spoofing"),
        _ev("autorun.inf exploit created on drive"),
        _ev("USB firmware modification tampering on controller"),
        _ev("exfiltrate data to USB flash drive storage"),
    ])
    assert many["risk_score"] >= few["risk_score"]
