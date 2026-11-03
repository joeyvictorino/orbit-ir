"""Tests for DDoS amplification detection module."""

import json
import os
import tempfile

from orbit_ir.ddos_amplification import analyze, classify_event, format_report, load_events


def _ev(**kw):
    return kw


def test_dns_amplification_detected():
    events = [_ev(detail="dns amplification attack using open resolver against target")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["dns_amplification"] >= 1


def test_ntp_amplification_detected():
    events = [_ev(detail="ntp amplification flood abusing monlist command")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["ntp_amplification"] >= 1


def test_memcached_amplification_detected():
    events = [_ev(detail="memcached amplification attack via udp reflection")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["memcached_amplification"] >= 1


def test_ssdp_amplification_detected():
    events = [_ev(detail="ssdp amplification flood targeting victim server")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["ssdp_amplification"] >= 1


def test_botnet_coordination_detected():
    events = [_ev(detail="coordinated ddos flood across multiple bot nodes and zombie drones")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["botnet_coordination"] >= 1


def test_application_layer_detected():
    events = [_ev(detail="slowloris attack connecting to exhaust server resources")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["application_layer"] >= 1


def test_http_flood_detected():
    events = [_ev(detail="http flood ddos attack exhausting web server resource connections")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["application_layer"] >= 1


def test_no_ddos_events():
    events = [_ev(detail="normal web request completed successfully")]
    r = analyze(events)
    assert r["ddos_events"] == 0
    assert r["risk_level"] == "none"


def test_empty_events():
    r = analyze([])
    assert r["total_events"] == 0
    assert r["ddos_events"] == 0


def test_risk_score_critical():
    events = [
        _ev(detail="dns amplification attack using open resolver against target"),
        _ev(detail="ntp amplification flood abusing monlist command"),
    ]
    r = analyze(events)
    assert r["risk_score"] > 0
    assert r["risk_level"] in ("critical", "high", "medium")


def test_agents_tracked():
    events = [
        _ev(agent_id="agent-1", detail="dns amplification attack using open resolver against target"),
        _ev(agent_id="agent-2", detail="ntp amplification flood abusing monlist command"),
    ]
    r = analyze(events)
    assert "agent-1" in r["agents_involved"]
    assert "agent-2" in r["agents_involved"]


def test_attack_campaigns():
    events = [
        _ev(agent_id="attacker", detail="dns amplification attack using open resolver against target"),
        _ev(agent_id="attacker", detail="ntp amplification flood abusing monlist command"),
    ]
    r = analyze(events)
    assert len(r["attack_campaigns"]) >= 1
    assert r["attack_campaigns"][0]["agent"] == "attacker"


def test_classify_event_no_match():
    result = classify_event({"detail": "user logged in successfully"})
    assert result["category"] == ""
    assert result["confidence"] == 0.0


def test_classify_event_with_match():
    result = classify_event({"detail": "dns amplification attack using open resolver against target"})
    assert result["category"] == "dns_amplification"
    assert result["confidence"] > 0


def test_format_report_output():
    events = [_ev(detail="dns amplification attack using open resolver against target")]
    r = analyze(events)
    text = format_report(r)
    assert "DDoS Amplification" in text
    assert "dns_amplification" in text


def test_format_report_empty():
    r = analyze([])
    text = format_report(r)
    assert "Total events: 0" in text


def test_load_events_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([{"detail": "dns amplification attack using open resolver against target"}], f)
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
    events = [_ev(detail="coordinated ddos flood from bot zombie drones plus dns amplification attack using open resolver against target")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"] if c["count"] > 0}
    assert len(cats) >= 2


def test_amplification_factor_tracked():
    events = [_ev(detail="dns amplification attack using open resolver against target", amplification_factor=54.0)]
    r = analyze(events)
    found = False
    for cs in r["categories"]:
        for ev in cs.get("events", []):
            if ev.get("amplification_factor", 0) == 54.0:
                found = True
    assert found


def test_dns_reflection_variant():
    events = [_ev(detail="dns reflection attack traffic flood against victim")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["dns_amplification"] >= 1
