"""Tests for API abuse pattern detection."""
from orbit_ir.api_abuse import (
    analyze_api_abuse,
    format_text,
    format_json,
)


def test_empty_events():
    r = analyze_api_abuse([])
    assert r.summary.total_detections == 0
    assert r.agent_scores == []
    assert r.summary.highest_severity == "none"


def test_no_abuse():
    events = [
        {"agent_id": "a1", "endpoint": "/api/data", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_api_abuse(events)
    assert r.summary.total_detections == 0


def test_rate_abuse():
    events = [
        {"agent_id": "a1", "endpoint": "/api/users", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(15)
    ]
    r = analyze_api_abuse(events)
    rate = [d for d in r.detections if d.abuse_type == "rate-abuse"]
    assert len(rate) >= 1
    assert "15 calls" in rate[0].description


def test_rate_below_threshold():
    events = [
        {"agent_id": "a1", "endpoint": "/api/users", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_api_abuse(events)
    rate = [d for d in r.detections if d.abuse_type == "rate-abuse"]
    assert len(rate) == 0


def test_endpoint_scrape():
    events = [
        {"agent_id": "a1", "endpoint": f"/api/endpoint{i}", "timestamp": "2025-01-01T00:01:00Z"}
        for i in range(10)
    ]
    r = analyze_api_abuse(events)
    scrapes = [d for d in r.detections if d.abuse_type == "endpoint-scrape"]
    assert len(scrapes) >= 1


def test_endpoint_scrape_below_threshold():
    events = [
        {"agent_id": "a1", "endpoint": f"/api/ep{i}", "timestamp": "2025-01-01T00:01:00Z"}
        for i in range(3)
    ]
    r = analyze_api_abuse(events)
    scrapes = [d for d in r.detections if d.abuse_type == "endpoint-scrape"]
    assert len(scrapes) == 0


def test_auth_bypass():
    events = [
        {"agent_id": "a1", "endpoint": "/api/admin",
         "headers": {"Authorization": "none"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    bypasses = [d for d in r.detections if d.abuse_type == "auth-bypass"]
    assert len(bypasses) >= 1
    assert bypasses[0].severity == "critical"


def test_auth_bypass_normal_ok():
    events = [
        {"agent_id": "a1", "endpoint": "/api/data",
         "headers": {"Authorization": "Bearer abc123"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    bypasses = [d for d in r.detections if d.abuse_type == "auth-bypass"]
    assert len(bypasses) == 0


def test_param_tamper():
    events = [
        {"agent_id": "a1", "endpoint": "/api/users",
         "params": {"role": "admin", "name": "test"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    tampers = [d for d in r.detections if d.abuse_type == "param-tamper"]
    assert len(tampers) >= 1


def test_param_tamper_normal_ok():
    events = [
        {"agent_id": "a1", "endpoint": "/api/search",
         "params": {"q": "hello", "page": "1"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    tampers = [d for d in r.detections if d.abuse_type == "param-tamper"]
    assert len(tampers) == 0


def test_data_extract():
    events = [
        {"agent_id": "a1", "endpoint": "/api/users?limit=10000",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    extracts = [d for d in r.detections if d.abuse_type == "data-extract"]
    assert len(extracts) >= 1


def test_data_extract_via_params():
    events = [
        {"agent_id": "a1", "endpoint": "/api/data",
         "params": {"export": "true"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    extracts = [d for d in r.detections if d.abuse_type == "data-extract"]
    assert len(extracts) >= 1


def test_data_extract_normal_ok():
    events = [
        {"agent_id": "a1", "endpoint": "/api/users?limit=10",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    extracts = [d for d in r.detections if d.abuse_type == "data-extract"]
    assert len(extracts) == 0


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "endpoint": "/api/admin",
         "headers": {"Authorization": "none"},
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "endpoint": "/api/data",
         "params": {"role": "admin"},
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_api_abuse(events)
    assert r.summary.agents_involved == 2


def test_agent_scores():
    events = [
        {"agent_id": "a1", "endpoint": "/api/admin",
         "headers": {"Authorization": "none"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    assert len(r.agent_scores) >= 1
    assert r.agent_scores[0].risk_score > 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "endpoint": "/api/admin",
         "headers": {"Authorization": "none"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    text = format_text(r)
    assert "API Abuse" in text
    assert "AA-" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "endpoint": "/api/admin",
         "headers": {"Authorization": "none"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_api_abuse([])
    text = format_text(r)
    assert "API Abuse" in text
    assert "0" in text


def test_endpoints_targeted():
    events = [
        {"agent_id": "a1", "endpoint": "/api/ep1", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "endpoint": "/api/ep2", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "endpoint": "/api/ep3", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_abuse(events)
    assert r.summary.endpoints_targeted == 3
