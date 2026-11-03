"""Tests for resource access topology analysis."""
from orbit_ir.resource_map import (
    analyze_resource_map,
    format_text,
    format_json,
    _resource_sensitivity,
    _sensitivity_label,
    _detect_escalation,
)


def test_empty_events():
    r = analyze_resource_map([])
    assert r.summary.total_agents == 0
    assert r.summary.total_resources == 0
    assert r.summary.total_edges == 0


def test_no_resource_events():
    events = [
        {"agent_id": "a1", "tool": "read_file", "effect": "file-read",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.total_edges == 0


def test_single_access():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.total_agents == 1
    assert r.summary.total_resources == 1
    assert r.summary.total_edges == 1


def test_sensitivity_scoring():
    assert _resource_sensitivity("secrets/api_key") == 5
    assert _resource_sensitivity("iam/policy.json") == 4
    assert _resource_sensitivity("acl/config") == 3
    assert _resource_sensitivity("config/app.yaml") == 2
    assert _resource_sensitivity("data/users.csv") == 1
    assert _resource_sensitivity("tmp/scratch") == 0


def test_sensitivity_labels():
    assert _sensitivity_label(5) == "critical"
    assert _sensitivity_label(4) == "high"
    assert _sensitivity_label(3) == "medium"
    assert _sensitivity_label(1) == "low"
    assert _sensitivity_label(0) == "none"


def test_concentration_detection():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": f"res{i}",
         "effect": "read", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(6)
    ]
    r = analyze_resource_map(events, concentration_threshold=5)
    assert r.summary.concentration_findings >= 1
    assert r.concentration[0].agent_id == "a1"
    assert r.concentration[0].unique_resources == 6


def test_concentration_sensitive():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key1",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key2",
         "effect": "read", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key3",
         "effect": "read", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_resource_map(events, concentration_threshold=100)
    assert r.summary.concentration_findings >= 1


def test_contention_detection():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "shared/db",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "write", "resource": "shared/db",
         "effect": "write", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_map(events, contention_threshold=2)
    assert r.summary.contention_findings >= 1
    assert "shared/db" == r.contention[0].resource
    assert sorted(r.contention[0].agents) == ["a1", "a2"]


def test_no_contention_single_agent():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "shared/db",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "write", "resource": "shared/db",
         "effect": "write", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_map(events, contention_threshold=2)
    assert r.summary.contention_findings == 0


def test_escalation_detection():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "tmp/scratch",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "data/users",
         "effect": "read", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/api_key",
         "effect": "read", "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "admin/panel",
         "effect": "read", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.escalation_findings >= 1
    esc = r.escalation[0]
    assert esc.final_sensitivity > esc.initial_sensitivity


def test_no_escalation_constant_sensitivity():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/k1",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/k2",
         "effect": "read", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.escalation_findings == 0


def test_resource_nodes():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "read", "resource": "secret/key",
         "effect": "read", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_map(events)
    res_node = [n for n in r.resource_nodes if n.resource == "secret/key"][0]
    assert res_node.sensitivity == 5
    assert res_node.sensitivity_label == "critical"
    assert res_node.access_count == 2
    assert sorted(res_node.agents) == ["a1", "a2"]


def test_agent_nodes():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "read", "resource": "data/file",
         "effect": "read", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_map(events)
    agent_node = [n for n in r.agent_nodes if n.agent_id == "a1"][0]
    assert agent_node.unique_resources == 2
    assert agent_node.resources_accessed == 2
    assert agent_node.max_sensitivity == 5
    assert agent_node.sensitive_accesses == 1


def test_multiple_agents_multiple_resources():
    events = [
        {"agent_id": "a1", "claimed_tool": "t", "resource": "secret/k",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "t", "resource": "data/f",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "claimed_tool": "t", "resource": "secret/k",
         "effect": "", "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a2", "claimed_tool": "t", "resource": "config/a",
         "effect": "", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.total_agents == 2
    assert r.summary.total_resources == 3
    assert r.summary.total_edges == 4


def test_format_text_output():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_map(events)
    text = format_text(r)
    assert "Resource Access Topology" in text
    assert "a1" in text
    assert "max_sens=5" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "claimed_tool": "read", "resource": "secret/key",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_map(events)
    import json
    data = json.loads(format_json(r))
    assert "agent_nodes" in data
    assert "resource_nodes" in data
    assert "summary" in data
    assert data["summary"]["total_agents"] == 1


def test_format_text_empty():
    r = analyze_resource_map([])
    text = format_text(r)
    assert "Resource Access Topology" in text
    assert "0" in text


def test_format_json_empty():
    r = analyze_resource_map([])
    import json
    data = json.loads(format_json(r))
    assert data["agent_nodes"] == []
    assert data["summary"]["total_edges"] == 0


def test_detect_escalation_direct():
    timelines = {
        "a1": [0, 1, 1, 3, 5, 5],
    }
    findings = _detect_escalation(timelines)
    assert len(findings) == 1
    assert findings[0].agent_id == "a1"
    assert findings[0].initial_sensitivity == 1
    assert findings[0].final_sensitivity == 5


def test_detect_escalation_no_increase():
    timelines = {
        "a1": [5, 5, 3, 3],
    }
    findings = _detect_escalation(timelines)
    assert len(findings) == 0


def test_edges_sorted_by_timestamp():
    events = [
        {"agent_id": "a1", "claimed_tool": "t", "resource": "r1",
         "effect": "", "timestamp": "2025-01-01T00:05:00Z"},
        {"agent_id": "a1", "claimed_tool": "t", "resource": "r2",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.edges[0].resource == "r2"
    assert r.edges[1].resource == "r1"


def test_skips_events_without_agent():
    events = [
        {"resource": "secret/key", "tool": "read",
         "effect": "read", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_map(events)
    assert r.summary.total_edges == 0


def test_contention_sorted_by_sensitivity():
    events = [
        {"agent_id": "a1", "claimed_tool": "t", "resource": "data/f",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "t", "resource": "data/f",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "t", "resource": "secret/k",
         "effect": "", "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a2", "claimed_tool": "t", "resource": "secret/k",
         "effect": "", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    r = analyze_resource_map(events, contention_threshold=2)
    assert r.contention[0].resource == "secret/k"
    assert r.contention[0].sensitivity > r.contention[1].sensitivity
