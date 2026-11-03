"""Tests for memory_injection detection module."""

import json
import os
import tempfile

from orbit_ir.memory_injection import (
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

def test_classify_process_injection():
    ev = _ev("dll inject into remote process detected")
    r = classify_event(ev)
    assert r["category"] == "process_injection"
    assert r["confidence"] > 0
    assert "process_injection" in r["indicators"]


def test_classify_process_injection_hollow():
    ev = _ev("process hollow technique used by agent")
    r = classify_event(ev)
    assert "process_injection" in r["indicators"]


def test_classify_process_injection_thread():
    ev = _ev("thread hijack detected in target process")
    r = classify_event(ev)
    assert "process_injection" in r["indicators"]


def test_classify_process_injection_api():
    ev = _ev("CreateRemoteThread call intercepted")
    r = classify_event(ev)
    assert "process_injection" in r["indicators"]


def test_classify_memory_manipulation():
    ev = _ev("VirtualAllocEx called on remote process")
    r = classify_event(ev)
    assert "memory_manipulation" in r["indicators"]


def test_classify_memory_manipulation_write():
    ev = _ev("WriteProcessMemory detected targeting svchost")
    r = classify_event(ev)
    assert "memory_manipulation" in r["indicators"]


def test_classify_memory_manipulation_direct():
    ev = _ev("direct memory write to remote process space")
    r = classify_event(ev)
    assert "memory_manipulation" in r["indicators"]


def test_classify_shellcode_execution():
    ev = _ev("shellcode load and execute in heap memory")
    r = classify_event(ev)
    assert "shellcode_execution" in r["indicators"]


def test_classify_shellcode_rop():
    ev = _ev("ROP chain gadget payload constructed")
    r = classify_event(ev)
    assert "shellcode_execution" in r["indicators"]


def test_classify_reflective_loading():
    ev = _ev("reflective DLL loading into target process")
    r = classify_event(ev)
    assert "reflective_loading" in r["indicators"]


def test_classify_reflective_inmemory():
    ev = _ev("in-memory PE load executed without disk write")
    r = classify_event(ev)
    assert "reflective_loading" in r["indicators"]


def test_classify_hook_installation():
    ev = _ev("API hook intercept installed on NtCreateFile")
    r = classify_event(ev)
    assert "hook_installation" in r["indicators"]


def test_classify_hook_iat():
    ev = _ev("IAT patch modification detected in kernel32")
    r = classify_event(ev)
    assert "hook_installation" in r["indicators"]


def test_classify_memory_scanning_evasion():
    ev = _ev("anti-debug memory technique deployed to evade scanning")
    r = classify_event(ev)
    assert "memory_scanning_evasion" in r["indicators"]


def test_classify_memory_guard():
    ev = _ev("page guard set manipulation to evade analysis")
    r = classify_event(ev)
    assert "memory_scanning_evasion" in r["indicators"]


def test_classify_no_match():
    ev = _ev("normal agent activity logging event")
    r = classify_event(ev)
    assert r["category"] == ""
    assert r["confidence"] == 0
    assert r["indicators"] == []


# ---- analyze ----

def test_analyze_empty():
    r = analyze([])
    assert r["total_events"] == 0
    assert r["memory_injection_events"] == 0
    assert r["risk_score"] == 0
    assert r["risk_level"] == "none"
    assert r["agents_involved"] == []
    assert r["attack_chains"] == []


def test_analyze_single():
    evts = [_ev("dll inject into remote process via CreateRemoteThread")]
    r = analyze(evts)
    assert r["total_events"] == 1
    assert r["memory_injection_events"] == 1
    assert r["risk_score"] > 0
    assert r["risk_level"] != "none"


def test_analyze_mixed():
    evts = [
        _ev("dll inject into remote process via thread hijack", agent="a1"),
        _ev("VirtualAllocEx remote memory allocation detected", agent="a1"),
        _ev("shellcode execute in heap spray region", agent="a2"),
        _ev("reflective DLL load into explorer.exe", agent="a2"),
        _ev("API hook detour installed on NtOpenProcess", agent="a3"),
        _ev("normal event no injection", agent="a4"),
    ]
    r = analyze(evts)
    assert r["total_events"] == 6
    assert r["memory_injection_events"] == 5
    assert r["risk_level"] in ("medium", "high", "critical")

    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["process_injection"] >= 1
    assert cats["memory_manipulation"] >= 1
    assert cats["shellcode_execution"] >= 1
    assert cats["reflective_loading"] >= 1
    assert cats["hook_installation"] >= 1


def test_analyze_all_critical():
    evts = [
        _ev("dll inject into remote process"),
        _ev("WriteProcessMemory to target"),
        _ev("shellcode load and execute payload"),
    ]
    r = analyze(evts)
    assert r["risk_level"] in ("high", "critical")


def test_analyze_agents():
    evts = [
        _ev("dll inject into remote process", agent="bot-1"),
        _ev("shellcode execute payload", agent="bot-2"),
    ]
    r = analyze(evts)
    assert sorted(r["agents_involved"]) == ["bot-1", "bot-2"]


# ---- chain detection ----

def test_chain_detection():
    evts = [
        _ev("dll inject into remote process", agent="a1"),
        _ev("VirtualAllocEx remote memory alloc", agent="a1"),
        _ev("shellcode execute in process", agent="a1"),
    ]
    r = analyze(evts)
    assert len(r["attack_chains"]) >= 1
    chain = r["attack_chains"][0]
    assert chain["agent"] == "a1"
    assert len(chain["steps"]) >= 2
    assert chain["chain_score"] > 0


def test_chain_multiple_agents():
    evts = [
        _ev("dll inject into remote process", agent="a1"),
        _ev("shellcode load payload", agent="a1"),
        _ev("API hook intercept installed", agent="a2"),
        _ev("IAT patch modification on ntdll", agent="a2"),
    ]
    r = analyze(evts)
    agents = [c["agent"] for c in r["attack_chains"]]
    assert "a1" in agents
    assert "a2" in agents


def test_chain_single_event_no_chain():
    evts = [_ev("dll inject into remote process", agent="solo")]
    r = analyze(evts)
    chains_for_solo = [c for c in r["attack_chains"] if c["agent"] == "solo"]
    assert len(chains_for_solo) == 0


# ---- format_report ----

def test_format_report_empty():
    r = analyze([])
    text = format_report(r)
    assert "Memory Injection Analysis" in text
    assert "Total events: 0" in text
    assert "Risk score: 0.00" in text


def test_format_report_with_data():
    evts = [
        _ev("dll inject into remote process", agent="a1"),
        _ev("VirtualAllocEx remote memory write", agent="a1"),
        _ev("shellcode execute payload in heap", agent="a2"),
    ]
    r = analyze(evts)
    text = format_report(r)
    assert "Memory Injection Analysis" in text
    assert "process_injection" in text
    assert "Attack chains:" in text


def test_format_report_categories():
    evts = [
        _ev("reflective DLL load into process"),
        _ev("API hook detour installed on api"),
        _ev("anti-debug memory evasion technique deployed"),
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
    evts = [_ev("dll inject into remote process")]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(evts, f)
        f.flush()
        loaded = load_events(f.name)
    os.unlink(f.name)
    assert len(loaded) == 1
    assert "dll inject" in loaded[0]["message"]


def test_load_events_single_dict():
    ev = _ev("VirtualAllocEx detected")
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
                json.dump([_ev(f"injection event {i}")], f)
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
        "process_injection", "memory_manipulation", "shellcode_execution",
        "reflective_loading", "hook_installation", "memory_scanning_evasion",
    }
    assert set(CATEGORIES.keys()) == expected


# ---- risk levels ----

def test_risk_level_none():
    r = analyze([_ev("normal benign event")])
    assert r["risk_level"] == "none"


def test_risk_level_scales():
    few = analyze([
        _ev("dll inject into remote process"),
        _ev("normal safe event nothing here"),
        _ev("another benign event no injection"),
        _ev("yet another clean event log entry"),
    ])
    many = analyze([
        _ev("dll inject into remote process"),
        _ev("WriteProcessMemory to target process"),
        _ev("shellcode load and execute payload"),
        _ev("reflective DLL load into explorer"),
    ])
    assert many["risk_score"] >= few["risk_score"]
