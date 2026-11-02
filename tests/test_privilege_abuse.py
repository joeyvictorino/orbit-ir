"""Tests for privilege abuse pattern detection."""
from orbit_ir.privilege_abuse import (
    analyze_privilege_abuse,
    format_text,
    format_json,
    _is_admin_tool,
    _get_role_level,
    _severity_for_abuse,
)


def test_empty_events():
    r = analyze_privilege_abuse([])
    assert r.summary.total_detections == 0
    assert r.agent_scores == []
    assert r.abuse_patterns == []


def test_no_abuse():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.total_detections == 0


def test_admin_tool_for_routine_task():
    events = [
        {"agent_id": "a1", "tool": "modify_policy", "resource": "policy/main",
         "purpose": "read status check", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].abuse_type == "opportunity-abuse"


def test_authority_bypass_low_role():
    events = [
        {"agent_id": "a1", "tool": "create_role", "resource": "roles/admin",
         "role": "viewer", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.total_detections >= 1
    assert any(d.abuse_type == "authority-bypass" for d in r.detections)


def test_authority_bypass_target_role():
    events = [
        {"agent_id": "a1", "tool": "assign_role", "resource": "roles/superadmin",
         "role": "editor", "target_role": "admin",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    bypasses = [d for d in r.detections if d.abuse_type == "authority-bypass"]
    assert len(bypasses) >= 1
    assert any(d.confidence == "high" for d in bypasses)


def test_cross_agent_access():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "agent-b/config",
         "resource_owner": "a2", "delegated": False,
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].abuse_type == "opportunity-abuse"
    assert "a2" in r.detections[0].description


def test_cross_agent_delegated_ok():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "agent-b/config",
         "resource_owner": "a2", "delegated": True,
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.total_detections == 0


def test_scope_creep():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "finance/report1.csv",
         "scope": "engineering data", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "finance/report2.csv",
         "scope": "engineering data", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "finance/report3.csv",
         "scope": "engineering data", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    creep = [d for d in r.detections if d.abuse_type == "scope-creep"]
    assert len(creep) >= 1


def test_in_scope_no_creep():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "engineering/code.py",
         "scope": "engineering data", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "engineering/tests.py",
         "scope": "engineering data", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    creep = [d for d in r.detections if d.abuse_type == "scope-creep"]
    assert len(creep) == 0


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "modify_policy", "resource": "policy/main",
         "purpose": "read check", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "read_file", "resource": "a1/secrets",
         "resource_owner": "a1", "delegated": False,
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert r.summary.agents_involved == 2


def test_abuse_patterns():
    events = [
        {"agent_id": "a1", "tool": "modify_policy", "resource": "p1",
         "purpose": "list check", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "update_iam", "resource": "p2",
         "purpose": "view status", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert len(r.abuse_patterns) >= 1
    assert r.abuse_patterns[0].occurrences >= 2


def test_agent_scores():
    events = [
        {"agent_id": "a1", "tool": "create_role", "resource": "roles/admin",
         "role": "viewer", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert len(r.agent_scores) >= 1
    assert r.agent_scores[0].risk_score > 0


def test_severity_critical_for_high_authority():
    events = [
        {"agent_id": "a1", "tool": "assume_role", "resource": "roles/root",
         "role": "viewer", "target_role": "root",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    assert any(d.severity == "critical" for d in r.detections)


def test_is_admin_tool():
    assert _is_admin_tool("create_role") is True
    assert _is_admin_tool("modify_policy") is True
    assert _is_admin_tool("update_iam") is True
    assert _is_admin_tool("read_file") is False


def test_get_role_level():
    assert _get_role_level("viewer") == 0
    assert _get_role_level("admin") == 3
    assert _get_role_level("root") == 4
    assert _get_role_level("unknown") == -1


def test_severity_for_abuse():
    assert _severity_for_abuse("authority-bypass", 3, "create_role") == "critical"
    assert _severity_for_abuse("authority-bypass", 1, "read_file") == "high"
    assert _severity_for_abuse("opportunity-abuse", 0, "read_file") == "medium"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "create_role", "resource": "roles/admin",
         "role": "viewer", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    text = format_text(r)
    assert "Privilege Abuse" in text
    assert "a1" in text
    assert "ABUSE-" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "create_role", "resource": "roles/admin",
         "role": "viewer", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_privilege_abuse([])
    text = format_text(r)
    assert "Privilege Abuse" in text
    assert "0" in text


def test_own_resources_ok():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "a1/output",
         "resource_owner": "a1", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_privilege_abuse(events)
    cross = [d for d in r.detections if "owned by" in d.description]
    assert len(cross) == 0
