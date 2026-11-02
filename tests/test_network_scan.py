"""Tests for network scanning detection."""
from orbit_ir.network_scan import (
    analyze_network_scans,
    format_text,
    format_json,
    _is_scan_tool,
    _is_recon_tool,
    _has_scan_indicator,
    _extract_port,
    _extract_host,
)


def test_empty_events():
    r = analyze_network_scans([])
    assert r.summary.total_port_sweeps == 0
    assert r.summary.total_host_enumerations == 0
    assert r.summary.total_service_discoveries == 0
    assert r.agents_involved == []


def test_no_scan_events():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_port_sweeps == 0


def test_port_sweep_detected():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"10.0.0.1:{p}",
         "effect": "port-scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, p in enumerate([22, 80, 443, 8080, 3306])
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_port_sweeps == 1
    ps = r.port_sweeps[0]
    assert ps.agent_id == "a1"
    assert ps.target_host == "10.0.0.1"
    assert ps.port_count == 5
    assert ps.confidence == "medium"


def test_port_sweep_high_confidence():
    events = [
        {"agent_id": "a1", "tool": "scan_port", "resource": f"10.0.0.1:{p}",
         "effect": "port-open", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, p in enumerate(range(20, 31))
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_port_sweeps == 1
    assert r.port_sweeps[0].confidence == "high"
    assert r.port_sweeps[0].port_count >= 10


def test_port_sweep_low_confidence():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"10.0.0.1:{p}",
         "effect": "scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, p in enumerate([22, 80, 443])
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_port_sweeps == 1
    assert r.port_sweeps[0].confidence == "low"


def test_host_enumeration_detected():
    events = [
        {"agent_id": "a1", "tool": "scan_host", "resource": f"10.0.0.{i}",
         "effect": "host-alive", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(1, 6)
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_host_enumerations == 1
    he = r.host_enumerations[0]
    assert he.agent_id == "a1"
    assert he.host_count >= 3


def test_host_enumeration_high_confidence():
    events = [
        {"agent_id": "a1", "tool": "scan_host", "resource": f"192.168.1.{i}",
         "effect": "host-alive", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(1, 15)
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_host_enumerations >= 1
    assert r.host_enumerations[0].confidence == "high"


def test_host_enumeration_via_recon():
    events = [
        {"agent_id": "a1", "tool": "dns_lookup", "resource": f"host-{i}.example.com",
         "effect": "resolved", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(1, 6)
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_host_enumerations >= 1


def test_service_discovery_detected():
    events = [
        {"agent_id": "a1", "tool": "scan_port", "resource": "10.0.0.1:22",
         "effect": "service-discovered-ssh", "timestamp": "2025-01-01T00:00:01Z"},
        {"agent_id": "a1", "tool": "scan_port", "resource": "10.0.0.1:80",
         "effect": "service-discovered-http", "timestamp": "2025-01-01T00:00:02Z"},
        {"agent_id": "a1", "tool": "scan_port", "resource": "10.0.0.1:443",
         "effect": "service-discovered-https", "timestamp": "2025-01-01T00:00:03Z"},
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_service_discoveries >= 1


def test_multiple_agents():
    events = []
    for agent in ["a1", "a2"]:
        events.extend([
            {"agent_id": agent, "tool": "port_scan", "resource": f"10.0.0.1:{p}",
             "effect": "port-scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
            for i, p in enumerate([22, 80, 443, 8080, 3306])
        ])
    r = analyze_network_scans(events)
    assert r.summary.agents_scanning == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_scan_rate_calculation():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"10.0.0.1:{p}",
         "effect": "scanned", "timestamp": f"2025-01-01T00:00:{i*10:02d}Z"}
        for i, p in enumerate([22, 80, 443, 8080, 3306])
    ]
    r = analyze_network_scans(events)
    assert r.summary.total_port_sweeps == 1
    assert r.port_sweeps[0].scan_rate > 0


def test_is_scan_tool():
    assert _is_scan_tool("port_scan") is True
    assert _is_scan_tool("nmap") is True
    assert _is_scan_tool("scan_host") is True
    assert _is_scan_tool("read_file") is False


def test_is_recon_tool():
    assert _is_recon_tool("dns_lookup") is True
    assert _is_recon_tool("ping") is True
    assert _is_recon_tool("write_file") is False


def test_has_scan_indicator():
    assert _has_scan_indicator({"tool": "check", "resource": "port/80", "effect": ""}) is True
    assert _has_scan_indicator({"tool": "read", "resource": "data.txt", "effect": ""}) is False


def test_extract_port():
    assert _extract_port("10.0.0.1:80") == 80
    assert _extract_port("host:443") == 443
    assert _extract_port("no-port-here") is None


def test_extract_host():
    assert _extract_host("10.0.0.1:80") == "10.0.0.1"
    assert _extract_host("server.example.com:443") == "server.example.com"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"10.0.0.1:{p}",
         "effect": "port-scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, p in enumerate([22, 80, 443, 8080, 3306])
    ]
    r = analyze_network_scans(events)
    text = format_text(r)
    assert "Network Scanning" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"10.0.0.1:{p}",
         "effect": "port-scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, p in enumerate([22, 80, 443, 8080, 3306])
    ]
    r = analyze_network_scans(events)
    import json
    data = json.loads(format_json(r))
    assert "port_sweeps" in data
    assert "summary" in data
    assert data["summary"]["total_port_sweeps"] == 1


def test_format_text_empty():
    r = analyze_network_scans([])
    text = format_text(r)
    assert "Network Scanning" in text
    assert "0" in text


def test_unique_targets():
    events = [
        {"agent_id": "a1", "tool": "port_scan", "resource": f"{host}:{p}",
         "effect": "scanned", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i, (host, p) in enumerate([
            ("10.0.0.1", 22), ("10.0.0.1", 80), ("10.0.0.1", 443),
            ("10.0.0.2", 22), ("10.0.0.2", 80), ("10.0.0.2", 443),
        ])
    ]
    r = analyze_network_scans(events)
    assert r.summary.unique_targets >= 1
