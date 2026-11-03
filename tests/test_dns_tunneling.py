"""Tests for DNS tunneling detection."""
from orbit_ir.dns_tunneling import (
    analyze_dns_tunneling,
    format_text,
    format_json,
    _is_dns_tool,
    _extract_domain,
    _extract_subdomains,
    _has_encoded_labels,
    _is_suspicious_tld,
)


def test_empty_events():
    r = analyze_dns_tunneling([])
    assert r.summary.total_tunnel_detections == 0
    assert r.summary.total_high_volume == 0
    assert r.summary.total_suspicious == 0
    assert r.agents_involved == []


def test_normal_dns_no_detection():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "api.example.com",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "dns_lookup", "resource": "cdn.example.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.total_tunnel_detections == 0


def test_tunnel_many_unique_subdomains():
    import base64
    events = []
    for i in range(15):
        payload = base64.b64encode(f"data-chunk-{i:04d}-exfiltration-payload".encode()).decode().rstrip("=")
        events.append({
            "agent_id": "a1",
            "tool": "dns_lookup",
            "resource": f"{payload}.evil.com",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    r = analyze_dns_tunneling(events)
    assert r.summary.total_tunnel_detections >= 1
    d = r.tunnel_detections[0]
    assert d.domain == "evil.com"
    assert d.has_encoding is True
    assert d.unique_subdomains >= 10


def test_tunnel_long_subdomains():
    events = []
    for i in range(5):
        long_label = "a" * 55 + str(i)
        events.append({
            "agent_id": "a1",
            "tool": "dns_lookup",
            "resource": f"{long_label}.exfil.net",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    r = analyze_dns_tunneling(events)
    assert r.summary.total_tunnel_detections >= 1
    d = r.tunnel_detections[0]
    assert d.max_subdomain_length > 50


def test_tunnel_txt_records():
    import base64
    events = []
    for i in range(5):
        payload = base64.b64encode(f"secret-data-{i}".encode()).decode()
        events.append({
            "agent_id": "a1",
            "tool": "dns_lookup",
            "resource": f"{payload}.tunnel.org",
            "record_type": "TXT",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    r = analyze_dns_tunneling(events)
    assert r.summary.total_tunnel_detections >= 1
    d = r.tunnel_detections[0]
    assert "TXT" in d.record_types


def test_high_volume_detection():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": f"sub{i}.flood.com",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(20)
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.total_high_volume >= 1
    hv = r.high_volume_queries[0]
    assert hv.queries_per_minute >= 10


def test_suspicious_long_label():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup",
         "resource": "a" * 55 + ".evil.com",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.total_suspicious >= 1
    assert "extremely long subdomain" in r.suspicious_queries[0].reason


def test_suspicious_dynamic_tld():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup",
         "resource": "c2server.duckdns.org",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dns_tunneling(events)
    assert r.summary.total_suspicious >= 1
    assert "dynamic DNS" in r.suspicious_queries[0].reason


def test_is_dns_tool():
    assert _is_dns_tool("dns_lookup") is True
    assert _is_dns_tool("resolve_host") is True
    assert _is_dns_tool("nslookup") is True
    assert _is_dns_tool("read_file") is False
    assert _is_dns_tool("http_get") is False


def test_extract_domain():
    assert _extract_domain("sub.example.com") == "example.com"
    assert _extract_domain("a.b.c.evil.org") == "evil.org"
    assert _extract_domain("example.com") == "example.com"
    assert _extract_domain("single") == "single"


def test_extract_subdomains():
    assert _extract_subdomains("a.b.example.com") == ["a", "b"]
    assert _extract_subdomains("example.com") == []
    assert _extract_subdomains("deep.sub.example.com") == ["deep", "sub"]


def test_has_encoded_labels():
    assert _has_encoded_labels(["aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="]) is True
    assert _has_encoded_labels(["abc"]) is False
    assert _has_encoded_labels(["0123456789abcdef" * 3]) is True


def test_is_suspicious_tld():
    assert _is_suspicious_tld("c2.duckdns.org") is True
    assert _is_suspicious_tld("api.example.com") is False
    assert _is_suspicious_tld("server.no-ip.org") is True


def test_multi_agent():
    events = []
    import base64
    for agent in ("a1", "a2"):
        for i in range(5):
            payload = base64.b64encode(f"exfil-{agent}-{i}".encode()).decode()
            events.append({
                "agent_id": agent,
                "tool": "dns_lookup",
                "resource": f"{payload}.bad.com",
                "timestamp": f"2025-01-01T00:{i:02d}:00Z",
            })
    r = analyze_dns_tunneling(events)
    assert r.summary.agents_involved >= 2


def test_format_text_output():
    import base64
    events = []
    for i in range(5):
        payload = base64.b64encode(f"data-{i}-secret".encode()).decode()
        events.append({
            "agent_id": "a1",
            "tool": "dns_lookup",
            "resource": f"{payload}.tunnel.com",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    r = analyze_dns_tunneling(events)
    text = format_text(r)
    assert "DNS Tunneling Detection Report" in text
    assert "tunnel.com" in text


def test_format_text_empty():
    r = analyze_dns_tunneling([])
    text = format_text(r)
    assert "Tunnel detections:    0" in text


def test_format_json_output():
    r = analyze_dns_tunneling([])
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "summary" in data
    assert data["summary"]["total_tunnel_detections"] == 0
