"""Tests for API key leak detection."""
from orbit_ir.api_key_leak import (
    analyze_api_key_leaks,
    format_text,
    format_json,
    _extract_output,
    _redact,
)


def test_empty_events():
    r = analyze_api_key_leaks([])
    assert r.summary.total_findings == 0
    assert r.agents_involved == []


def test_no_leaks():
    events = [
        {"agent_id": "a1", "tool": "read_file", "output": "normal text output here",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.total_findings == 0


def test_aws_key_leak():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "Found key: AKIAIOSFODNN7EXAMPLE",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.api_key_in_output >= 1
    assert r.findings[0].pattern == "api_key_in_output"
    assert r.findings[0].confidence == "high"


def test_openai_key_leak():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "Using key sk-abcdefghijklmnopqrstuvwxyz1234567890",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.api_key_in_output >= 1


def test_bearer_token():
    events = [
        {"agent_id": "a1", "tool": "http_request",
         "output": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA==",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.bearer_token_exposure >= 1
    assert r.findings[0].pattern == "bearer_token_exposure"


def test_password_plaintext():
    events = [
        {"agent_id": "a1", "tool": "config_read",
         "output": "password=SuperSecret123!",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.password_in_plaintext >= 1
    assert r.findings[0].pattern == "password_in_plaintext"


def test_connection_string():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "Connecting to postgres://admin:hunter2@db.example.com:5432/prod",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.connection_string_leak >= 1
    assert r.findings[0].pattern == "connection_string_leak"


def test_private_key():
    events = [
        {"agent_id": "a1", "tool": "file_read",
         "output": "-----BEGIN RSA PRIVATE KEY----- MIIEpQIBAAKCAQ...",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.private_key_material >= 1
    assert r.findings[0].pattern == "private_key_material"


def test_credential_in_url():
    events = [
        {"agent_id": "a1", "tool": "fetch",
         "output": "Fetching https://user:password123@api.example.com/data",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.credential_in_url >= 1
    assert r.findings[0].pattern == "credential_in_url"


def test_extract_output():
    assert _extract_output({"output": "hello"}) == "hello"
    assert _extract_output({"response": "world"}) == "world"
    assert _extract_output({}) == ""


def test_redact():
    assert _redact("short") == "short"
    assert _redact("AKIAIOSFODNN7EXAMPLE").startswith("AKIAIO")
    assert "..." in _redact("AKIAIOSFODNN7EXAMPLE")


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "Found key: AKIAIOSFODNN7EXAMPLE",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    text = format_text(r)
    assert "API Key" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "Found key: AKIAIOSFODNN7EXAMPLE",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "findings" in data
    assert "summary" in data


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "shell",
         "output": "key: AKIAIOSFODNN7EXAMPLE",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "fetch",
         "output": "https://admin:pass1234@host.com/api",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_api_key_leaks(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]
