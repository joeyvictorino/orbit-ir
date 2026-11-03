"""Tests for shadow API detection."""
from orbit_ir.shadow_api import (
    analyze_shadow_apis,
    format_text,
    format_json,
    _extract_endpoint,
    _is_api_event,
)


def test_empty_events():
    r = analyze_shadow_apis([])
    assert r.summary.total_findings == 0
    assert r.agents_involved == []


def test_no_shadow_api():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.total_findings == 0


def test_debug_api():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/debug/dump",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.debug_api >= 1
    assert r.findings[0].pattern == "shadow_debug_api"
    assert r.findings[0].confidence == "high"


def test_deprecated_api():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/v0/users",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.deprecated_api >= 1
    assert r.findings[0].pattern == "shadow_deprecated_api"
    assert r.findings[0].confidence == "medium"


def test_internal_api():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://10.0.1.5/internal/admin",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.internal_api >= 1
    assert r.findings[0].pattern == "shadow_internal_api"


def test_hidden_parameter():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/users",
         "parameters": "__admin=true&__bypass=1",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.hidden_parameter >= 1
    assert r.findings[0].pattern == "shadow_hidden_parameter"


def test_version_mismatch():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/v2/data",
         "parameters": "api_version=3",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.version_mismatch >= 1
    assert r.findings[0].pattern == "shadow_version_mismatch"


def test_undocumented_endpoint():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/secret",
         "response": "404 not found fallback to legacy",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.undocumented_endpoint >= 1
    assert r.findings[0].pattern == "shadow_undocumented_endpoint"


def test_extract_endpoint():
    assert _extract_endpoint({"resource": "https://x.com"}) == "https://x.com"
    assert _extract_endpoint({"target": "https://y.com"}) == "https://y.com"
    assert _extract_endpoint({}) == ""


def test_is_api_event():
    assert _is_api_event({"tool": "http_request"}) is True
    assert _is_api_event({"tool": "read_file"}) is False
    assert _is_api_event({"tool": "foo", "resource": "https://api.example.com/v1/data"}) is True


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/debug/info",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    text = format_text(r)
    assert "Shadow API" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/debug/info",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_shadow_apis(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "findings" in data
    assert "summary" in data


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "resource": "https://api.example.com/debug/dump",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "fetch",
         "resource": "https://10.0.1.5/internal/config",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_shadow_apis(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]
