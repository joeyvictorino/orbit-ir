"""Tests for ssl_stripping detection module."""

import json
import os
import tempfile

from orbit_ir.ssl_stripping import (
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


def test_classify_https_downgrade():
    ev = {"message": "https downgraded to http stripping encryption from connection"}
    result = classify_event(ev)
    assert result["category"] == "https_downgrade"
    assert result["confidence"] > 0


def test_classify_sslstrip():
    ev = {"message": "sslstrip tool active intercepting and stripping SSL"}
    result = classify_event(ev)
    assert "https_downgrade" in result["indicators"]


def test_classify_strip_ssl():
    ev = {"message": "stripping ssl encryption from traffic in transit"}
    result = classify_event(ev)
    assert result["category"] == "https_downgrade"


def test_classify_certificate_spoofing():
    ev = {"message": "certificate spoofed with forged self-signed cert presented to client"}
    result = classify_event(ev)
    assert result["category"] == "certificate_spoofing"
    assert result["confidence"] > 0


def test_classify_self_signed_cert():
    ev = {"message": "self-signed certificate detected for ssl connection to banking site"}
    result = classify_event(ev)
    assert "certificate_spoofing" in result["indicators"]


def test_classify_fake_cert_injection():
    ev = {"message": "presenting fake certificate to unsuspecting tls client"}
    result = classify_event(ev)
    assert "certificate_spoofing" in result["indicators"]


def test_classify_hsts_bypass():
    ev = {"message": "hsts bypass stripping strict-transport-security header from response"}
    result = classify_event(ev)
    assert result["category"] == "hsts_bypass"


def test_classify_hsts_header_removal():
    ev = {"message": "strip hsts header removing strict-transport bypass policy"}
    result = classify_event(ev)
    assert "hsts_bypass" in result["indicators"]


def test_classify_tls_interception():
    ev = {"message": "tls interception mitm proxy certificate injected into trust store"}
    result = classify_event(ev)
    assert result["category"] == "tls_interception"


def test_classify_mitm_tls():
    ev = {"message": "man-in-the-middle tls ssl proxy intercepting encrypted traffic"}
    result = classify_event(ev)
    assert "tls_interception" in result["indicators"]


def test_classify_protocol_downgrade():
    ev = {"message": "tls version downgraded to tls 1.0 forcing weak protocol fallback"}
    result = classify_event(ev)
    assert result["category"] == "protocol_downgrade"


def test_classify_poodle_attack():
    ev = {"message": "poodle attack exploiting ssl 3.0 vulnerability downgrade"}
    result = classify_event(ev)
    assert "protocol_downgrade" in result["indicators"]


def test_classify_cipher_downgrade():
    ev = {"message": "cipher suite forced negotiation to accept weak export ciphers by tls protocol downgraded fallback"}
    result = classify_event(ev)
    assert "protocol_downgrade" in result["indicators"]


def test_classify_mixed_content():
    ev = {"message": "mixed content exploit injecting http resource script into https secure page"}
    result = classify_event(ev)
    assert result["category"] == "mixed_content_exploit"


def test_classify_insecure_resource_load():
    ev = {"message": "mixed content inject loading http resource script into https page exploit"}
    result = classify_event(ev)
    assert "mixed_content_exploit" in result["indicators"]


def test_classify_benign():
    ev = {"message": "normal encrypted connection established successfully"}
    result = classify_event(ev)
    assert result["category"] == ""
    assert result["confidence"] == 0
    assert result["indicators"] == []


def test_analyze_empty():
    result = analyze([])
    assert result["total_events"] == 0
    assert result["ssl_stripping_events"] == 0
    assert result["risk_level"] == "none"


def test_analyze_mixed_events():
    events = [
        {"agent_id": "a1", "message": "https downgraded to http stripping ssl encryption"},
        {"agent_id": "a1", "message": "certificate spoofed forged fake cert presented"},
        {"agent_id": "a2", "message": "normal https connection ok"},
        {"agent_id": "a2", "message": "hsts bypass stripping strict-transport header"},
    ]
    result = analyze(events)
    assert result["total_events"] == 4
    assert result["ssl_stripping_events"] == 3
    assert result["risk_score"] > 0
    assert len(result["agents_involved"]) == 2


def test_analyze_risk_levels():
    events = [
        {"agent_id": "a1", "message": "https downgraded to http stripping connection"},
        {"agent_id": "a1", "message": "certificate spoofed with fake self-signed cert"},
    ]
    result = analyze(events)
    assert result["risk_level"] in ("critical", "high")


def test_analyze_categories_populated():
    events = [
        {"message": "https downgraded to http stripping ssl encryption"},
        {"message": "tls interception mitm proxy certificate injected"},
    ]
    result = analyze(events)
    cats = {c["category"]: c for c in result["categories"]}
    assert "https_downgrade" in cats
    assert cats["https_downgrade"]["count"] >= 1


def test_analyze_attack_chains():
    events = [
        {"agent_id": "strip-agent", "message": "https downgraded to http stripping ssl"},
        {"agent_id": "strip-agent", "message": "certificate spoofed forged fake cert presented"},
        {"agent_id": "strip-agent", "message": "hsts bypass stripping strict-transport header"},
    ]
    result = analyze(events)
    assert len(result["attack_chains"]) >= 1
    chain = result["attack_chains"][0]
    assert chain["agent"] == "strip-agent"
    assert len(chain["categories_seen"]) >= 2


def test_format_report_basic():
    events = [
        {"agent_id": "a1", "message": "https downgraded to http stripping ssl"},
    ]
    result = analyze(events)
    report = format_report(result)
    assert "SSL/TLS Stripping Analysis" in report
    assert "https_downgrade" in report


def test_format_report_empty():
    result = analyze([])
    report = format_report(result)
    assert "Total events: 0" in report


def test_format_report_with_chains():
    events = [
        {"agent_id": "x", "message": "https downgraded to http stripping ssl"},
        {"agent_id": "x", "message": "tls interception mitm proxy intercepting traffic"},
    ]
    result = analyze(events)
    report = format_report(result)
    assert "Attack chains:" in report


def test_load_events_file(tmp_path):
    data = [{"message": "ssl strip event"}, {"message": "benign"}]
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


def test_analyze_no_raw_in_output():
    events = [
        {"agent_id": "a1", "message": "https downgraded to http stripping ssl"},
    ]
    result = analyze(events)
    for cs in result["categories"]:
        for ev in cs.get("events", []):
            assert "raw" not in ev
    for chain in result.get("attack_chains", []):
        for step in chain.get("steps", []):
            assert "raw" not in step


def test_analyze_agents_sorted():
    events = [
        {"agent_id": "z-agent", "message": "https downgraded to http stripping ssl"},
        {"agent_id": "a-agent", "message": "certificate spoofed forged cert"},
    ]
    result = analyze(events)
    agents = result["agents_involved"]
    assert agents == sorted(agents)
