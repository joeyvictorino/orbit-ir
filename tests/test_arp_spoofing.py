"""Tests for ARP spoofing/poisoning detection module."""

import json
import os
import tempfile

from orbit_ir.arp_spoofing import analyze, classify_event, format_report, load_events


def _ev(**kw):
    return kw


def test_arp_cache_poisoning_detected():
    events = [_ev(detail="arp cache poisoning attack corrupting table entries")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["arp_cache_poisoning"] >= 1


def test_arp_reply_spoofing():
    events = [_ev(detail="forged arp reply packet sent to victim host")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["arp_cache_poisoning"] >= 1


def test_gratuitous_arp_flood_detected():
    events = [_ev(detail="gratuitous arp flood broadcast injected on network segment")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["gratuitous_arp_flood"] >= 1


def test_gateway_impersonation_detected():
    events = [_ev(detail="impersonating default gateway mac address via arp spoof")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["gateway_impersonation"] >= 1


def test_gateway_mac_spoofing():
    events = [_ev(detail="gateway mac spoofed to redirect all network traffic")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["gateway_impersonation"] >= 1


def test_mac_flapping_detected():
    events = [_ev(detail="mac address flapping detected on switch port rapid changes")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["mac_flapping"] >= 1


def test_rapid_mac_changes():
    events = [_ev(detail="rapid mac address changes detected on network interface")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["mac_flapping"] >= 1


def test_mitm_via_arp_detected():
    events = [_ev(detail="man-in-the-middle via arp spoofing attack established")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["mitm_via_arp"] >= 1


def test_arp_intercept():
    events = [_ev(detail="intercept traffic via arp spoofing to capture packets")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["mitm_via_arp"] >= 1


def test_arp_scan_recon_detected():
    events = [_ev(detail="arp scan network subnet for host discovery and enumeration")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["arp_scan_recon"] >= 1


def test_no_arp_events():
    events = [_ev(detail="normal web request completed successfully")]
    r = analyze(events)
    assert r["arp_events"] == 0
    assert r["risk_level"] == "none"


def test_empty_events():
    r = analyze([])
    assert r["total_events"] == 0
    assert r["arp_events"] == 0


def test_risk_score_calculated():
    events = [
        _ev(detail="arp cache poisoning attack corrupting table entries"),
        _ev(detail="man-in-the-middle via arp spoofing attack established"),
    ]
    r = analyze(events)
    assert r["risk_score"] > 0
    assert r["risk_level"] in ("critical", "high", "medium")


def test_agents_tracked():
    events = [
        _ev(agent_id="agent-1", detail="arp cache poisoning attack corrupting table entries"),
        _ev(agent_id="agent-2", detail="gratuitous arp flood broadcast injected on network segment"),
    ]
    r = analyze(events)
    assert "agent-1" in r["agents_involved"]
    assert "agent-2" in r["agents_involved"]


def test_attack_chains():
    events = [
        _ev(agent_id="attacker", detail="arp scan network subnet for host discovery and enumeration"),
        _ev(agent_id="attacker", detail="arp cache poisoning attack corrupting table entries"),
    ]
    r = analyze(events)
    assert len(r["attack_chains"]) >= 1
    assert r["attack_chains"][0]["agent"] == "attacker"


def test_classify_event_no_match():
    result = classify_event({"detail": "user logged in successfully"})
    assert result["category"] == ""
    assert result["confidence"] == 0.0


def test_classify_event_with_match():
    result = classify_event({"detail": "arp cache poisoning attack corrupting table entries"})
    assert result["category"] == "arp_cache_poisoning"
    assert result["confidence"] > 0


def test_format_report_output():
    events = [_ev(detail="arp cache poisoning attack corrupting table entries")]
    r = analyze(events)
    text = format_report(r)
    assert "ARP Spoofing" in text
    assert "arp_cache_poisoning" in text


def test_format_report_empty():
    r = analyze([])
    text = format_report(r)
    assert "Total events: 0" in text


def test_load_events_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([{"detail": "arp cache poisoning attack corrupting table entries"}], f)
        f.flush()
        events = load_events(f.name)
    os.unlink(f.name)
    assert len(events) == 1


def test_load_events_missing():
    events = load_events("/nonexistent/path")
    assert events == []


def test_load_events_directory():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "ev.json")
        with open(p, "w") as f:
            json.dump([{"detail": "test event"}], f)
        events = load_events(d)
    assert len(events) == 1


def test_multiple_categories_single_event():
    events = [_ev(detail="arp scan network subnet for host discovery then arp cache poisoning attack corrupting entries")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"] if c["count"] > 0}
    assert len(cats) >= 2


def test_source_mac_tracked():
    events = [_ev(detail="arp cache poisoning attack corrupting table entries", source_mac="aa:bb:cc:dd:ee:ff")]
    r = analyze(events)
    found = False
    for cs in r["categories"]:
        for ev in cs.get("events", []):
            if ev.get("source_mac") == "aa:bb:cc:dd:ee:ff":
                found = True
    assert found
