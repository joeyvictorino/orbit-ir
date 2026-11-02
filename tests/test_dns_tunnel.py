"""Tests for DNS tunneling detection."""
from orbit_ir.dns_tunnel import (
    analyze_dns_tunneling,
    format_text,
    format_json,
    _shannon_entropy,
    _extract_subdomain,
    _is_known_tunnel_domain,
)


def test_empty_events():
    r = analyze_dns_tunneling([])
    assert r.summary.total_findings == 0
    assert r.agents_involved == []


def test_no_tunneling():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.total_findings == 0


def test_high_entropy_subdomain():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "aGVsbG8gd29ybGQ.x3f2k9.evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.high_entropy >= 1
    assert r.findings[0].pattern == "dns_high_entropy_subdomain"
    assert r.findings[0].agent_id == "a1"


def test_txt_record_abuse():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": f"data{i}.evil.com",
         "query_type": "TXT", "timestamp": f"2025-01-01T00:0{i}:00Z"}
        for i in range(6)
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.txt_abuse >= 1
    found = [f for f in r.findings if f.pattern == "dns_txt_record_abuse"]
    assert len(found) >= 1
    assert found[0].confidence in ("medium", "high")


def test_volume_spike():
    events = [
        {"agent_id": "a1", "tool": "dns_resolve", "resource": f"host{i}.example.com",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(55)
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.volume_spike >= 1


def test_long_subdomain():
    long_label = "a" * 64
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": f"{long_label}.evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.long_subdomain >= 1
    assert r.findings[0].pattern == "dns_long_subdomain"


def test_known_tunnel_domain():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "data.dnscat.attacker.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.known_tunnel >= 1
    assert r.findings[0].pattern == "dns_known_tunnel_domain"
    assert r.findings[0].confidence == "high"


def test_periodic_beacon():
    events = [
        {"agent_id": "a1", "tool": "dns_resolve", "resource": "beacon.evil.com",
         "timestamp": f"2025-01-01T00:{i*5:02d}:00Z"}
        for i in range(6)
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.periodic_beacon >= 1
    found = [f for f in r.findings if f.pattern == "dns_periodic_beacon"]
    assert len(found) >= 1


def test_shannon_entropy():
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("abcd") > 1.0


def test_extract_subdomain():
    assert _extract_subdomain("evil.com") == ""
    assert _extract_subdomain("sub.evil.com") == "sub"
    assert _extract_subdomain("a.b.evil.com") == "a.b"


def test_is_known_tunnel_domain():
    assert _is_known_tunnel_domain("data.dnscat.com") is True
    assert _is_known_tunnel_domain("google.com") is False


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "data.dnscat.evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    text = format_text(r)
    assert "DNS Tunneling" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "data.dnscat.evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "findings" in data
    assert "summary" in data


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "data.dnscat.evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "dns_resolve", "resource": "exfil.iodine.attacker.com",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]
