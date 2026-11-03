"""Tests for dns_hijack detection module."""

import json
import os
import tempfile

from orbit_ir.dns_hijack import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


def test_categories_structure():
    assert len(CATEGORIES) == 6
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 2


def test_classify_dns_spoofing():
    ev = {"message": "dns spoofed response detected for target domain"}
    result = classify_event(ev)
    assert result["category"] == "dns_spoofing"
    assert result["confidence"] > 0


def test_classify_cache_poisoning():
    ev = {"message": "cache poisoned dns record injected into resolver cache"}
    result = classify_event(ev)
    assert "dns_spoofing" in result["indicators"]


def test_classify_pharming():
    ev = {"message": "pharming attack redirecting users to malicious site"}
    result = classify_event(ev)
    assert result["category"] == "dns_spoofing"


def test_classify_dns_rebinding():
    ev = {"message": "dns rebinding attack bypassing same-origin policy to internal network"}
    result = classify_event(ev)
    assert result["category"] == "dns_rebinding"
    assert result["confidence"] > 0


def test_classify_internal_ip_resolution():
    ev = {"message": "internal ip address resolution dns domain resolving 192.168.1.1"}
    result = classify_event(ev)
    assert "dns_rebinding" in result["indicators"]


def test_classify_dns_tunneling():
    ev = {"message": "dns tunnel data exfiltration channel established over subdomain queries"}
    result = classify_event(ev)
    assert result["category"] == "dns_tunneling_exfil"


def test_classify_txt_record_exfil():
    ev = {"message": "txt record query encoding hidden data in exfiltration via dns"}
    result = classify_event(ev)
    assert "dns_tunneling_exfil" in result["indicators"]


def test_classify_domain_takeover():
    ev = {"message": "subdomain takeover discovered with dangling CNAME record pointing to unclaimed resource"}
    result = classify_event(ev)
    assert result["category"] == "domain_takeover"


def test_classify_dangling_cname():
    ev = {"message": "dangling dns cname record found pointing to expired subdomain service"}
    result = classify_event(ev)
    assert "domain_takeover" in result["indicators"]


def test_classify_dns_amplification():
    ev = {"message": "dns amplification ddos attack using open resolver abuse"}
    result = classify_event(ev)
    assert result["category"] == "dns_amplification"


def test_classify_nxdomain_hijack():
    ev = {"message": "nxdomain hijack redirect nonexistent domain dns intercept rewrite"}
    result = classify_event(ev)
    assert "nxdomain_hijack" in result["indicators"]


def test_classify_wildcard_dns():
    ev = {"message": "wildcard dns record manipulated to abuse redirect traffic via ISP dns hijack redirect"}
    result = classify_event(ev)
    assert "nxdomain_hijack" in result["indicators"]


def test_classify_benign():
    ev = {"message": "normal web request completed successfully"}
    result = classify_event(ev)
    assert result["category"] == ""
    assert result["confidence"] == 0
    assert result["indicators"] == []


def test_analyze_empty():
    result = analyze([])
    assert result["total_events"] == 0
    assert result["dns_hijack_events"] == 0
    assert result["risk_level"] == "none"


def test_analyze_mixed_events():
    events = [
        {"agent_id": "a1", "message": "dns spoofed response forged for target domain"},
        {"agent_id": "a1", "message": "dns rebinding attack bypass internal network"},
        {"agent_id": "a2", "message": "normal dns query completed ok"},
        {"agent_id": "a2", "message": "subdomain takeover hijack of dangling record"},
    ]
    result = analyze(events)
    assert result["total_events"] == 4
    assert result["dns_hijack_events"] == 3
    assert result["risk_score"] > 0
    assert len(result["agents_involved"]) == 2


def test_analyze_risk_levels():
    critical_events = [
        {"agent_id": "a1", "message": "dns spoofed response forged for domain"},
        {"agent_id": "a1", "message": "dns rebinding attack bypass internal network"},
    ]
    result = analyze(critical_events)
    assert result["risk_level"] in ("critical", "high")


def test_analyze_categories_populated():
    events = [
        {"message": "dns spoofed response forged for domain"},
        {"message": "dns tunnel exfiltration data over subdomain queries"},
    ]
    result = analyze(events)
    cats = {c["category"]: c for c in result["categories"]}
    assert "dns_spoofing" in cats
    assert cats["dns_spoofing"]["count"] >= 1


def test_analyze_attack_chains():
    events = [
        {"agent_id": "attacker", "message": "dns spoofed response forged for target domain"},
        {"agent_id": "attacker", "message": "dns rebinding attack bypass to internal ip"},
        {"agent_id": "attacker", "message": "dns tunnel data exfiltration via subdomain"},
    ]
    result = analyze(events)
    assert len(result["attack_chains"]) >= 1
    chain = result["attack_chains"][0]
    assert chain["agent"] == "attacker"
    assert len(chain["categories_seen"]) >= 2


def test_format_report_basic():
    events = [
        {"agent_id": "a1", "message": "dns spoofed response forged for domain"},
    ]
    result = analyze(events)
    report = format_report(result)
    assert "DNS Hijacking Analysis" in report
    assert "dns_spoofing" in report


def test_format_report_empty():
    result = analyze([])
    report = format_report(result)
    assert "Total events: 0" in report


def test_format_report_attack_chains():
    events = [
        {"agent_id": "x", "message": "dns spoofed response forged for domain"},
        {"agent_id": "x", "message": "dns amplification ddos flood attack"},
    ]
    result = analyze(events)
    report = format_report(result)
    assert "Attack chains:" in report


def test_load_events_file(tmp_path):
    data = [{"message": "dns spoofed record"}, {"message": "benign"}]
    f = tmp_path / "events.json"
    f.write_text(json.dumps(data))
    events = load_events(str(f))
    assert len(events) == 2


def test_load_events_directory(tmp_path):
    for i in range(3):
        f = tmp_path / f"ev_{i}.json"
        f.write_text(json.dumps([{"id": i}]))
    events = load_events(str(tmp_path))
    assert len(events) == 3


def test_load_events_nonexistent():
    events = load_events("/nonexistent/path")
    assert events == []


def test_load_events_single_dict(tmp_path):
    f = tmp_path / "single.json"
    f.write_text(json.dumps({"message": "one event"}))
    events = load_events(str(f))
    assert len(events) == 1


def test_load_events_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not valid json{{{")
    events = load_events(str(f))
    assert events == []


def test_classify_multi_indicator():
    ev = {"message": "dns spoofed forged response with cache poisoned dns record injection"}
    result = classify_event(ev)
    assert len(result["indicators"]) >= 1
    assert result["confidence"] > 0.3


def test_analyze_domain_extraction():
    events = [
        {"agent_id": "a1", "message": "dns spoofed forged response for example.com target domain"},
    ]
    result = analyze(events)
    cats = {c["category"]: c for c in result["categories"]}
    spoofing = cats.get("dns_spoofing", {})
    if spoofing.get("events"):
        ev = spoofing["events"][0]
        assert "domain" in ev or "detail" in ev


def test_analyze_no_raw_in_output():
    events = [
        {"agent_id": "a1", "message": "dns spoofed response forged for domain"},
    ]
    result = analyze(events)
    for cs in result["categories"]:
        for ev in cs.get("events", []):
            assert "raw" not in ev
    for chain in result.get("attack_chains", []):
        for step in chain.get("steps", []):
            assert "raw" not in step
