"""Tests for privilege escalation detection."""
from orbit_ir.privesc import (
    analyze_privilege_escalation,
    format_text,
    format_json,
    _is_sensitive_resource,
    _is_sensitive_effect,
    _is_escalation_tool,
    _classify_step_reason,
)


def test_empty_events():
    r = analyze_privilege_escalation([], [])
    assert r.summary.total_paths == 0
    assert r.agents_involved == []
    assert r.credential_chains == []


def test_no_escalation():
    events = [
        {"agent_id": "a1", "claimed_tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z",
         "tool_call_id": "tc1", "credential_id": "", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation(events, [])
    assert r.summary.total_paths == 0


def test_sensitive_resource_access():
    control = [
        {"agent_id": "a1", "actual_tool": "read_config", "resource": "iam/policy.json",
         "effect": "file-read", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.summary.total_paths == 1
    assert r.paths[0].severity in ("medium", "high")
    assert "iam/policy.json" in r.paths[0].resources_touched


def test_privilege_tool_invoked():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.summary.total_paths == 1
    assert r.paths[0].severity == "high"


def test_privilege_tool_with_sensitive_effect():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
        {"agent_id": "a1", "actual_tool": "grant_permission", "resource": "perms/all",
         "effect": "permission-granted", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.paths[0].severity == "critical"


def test_bypassed_policy_denial():
    control = [
        {"agent_id": "a1", "actual_tool": "write_file", "resource": "secret/keys.json",
         "effect": "secret-written", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "denied"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.summary.total_paths == 1
    assert r.paths[0].severity == "critical"
    assert any(s.reason == "bypassed-policy-denial" for s in r.paths[0].steps)


def test_multi_step_escalation():
    control = [
        {"agent_id": "a1", "actual_tool": "read_config", "resource": "iam/roles",
         "effect": "file-read", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
        {"agent_id": "a1", "actual_tool": "create_token", "resource": "tokens/admin-token",
         "effect": "token-minted", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "cred-1", "policy_decision": "allowed"},
        {"agent_id": "a1", "actual_tool": "modify_policy", "resource": "policy/main",
         "effect": "policy-modified", "timestamp": "2025-01-01T00:03:00Z",
         "tool_call_id": "tc3", "credential_id": "cred-2", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.summary.total_paths == 1
    path = r.paths[0]
    assert len(path.steps) == 3
    assert path.severity == "critical"
    assert "cred-1" in path.credentials_used
    assert "cred-2" in path.credentials_used


def test_multiple_agents():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/editor",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
        {"agent_id": "a2", "actual_tool": "modify_acl", "resource": "acl/main",
         "effect": "access-control-modified", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "cred-2", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.summary.total_paths == 2
    assert r.summary.agents_escalating == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_credential_chain():
    control = [
        {"agent_id": "a1", "actual_tool": "create_token", "resource": "tokens/t1",
         "effect": "token-minted", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "shared-cred", "policy_decision": "allowed"},
        {"agent_id": "a2", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "privilege-escalated", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "shared-cred", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert len(r.credential_chains) >= 1
    chain = r.credential_chains[0]
    assert chain["credential_id"] == "shared-cred"
    assert chain["shared"] is True
    assert "a1" in chain["agents"]
    assert "a2" in chain["agents"]


def test_role_change():
    control = [
        {"agent_id": "a1", "actual_tool": "assume_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed",
         "role": "viewer"},
        {"agent_id": "a1", "actual_tool": "modify_policy", "resource": "policy/main",
         "effect": "policy-modified", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "cred-1", "policy_decision": "allowed",
         "role": "admin"},
    ]
    r = analyze_privilege_escalation([], control)
    path = r.paths[0]
    assert path.initial_role == "viewer"
    assert path.final_role == "admin"


def test_severity_ordering():
    control = [
        {"agent_id": "low-agent", "actual_tool": "read_config", "resource": "secret/x",
         "effect": "file-read", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "", "policy_decision": "allowed"},
        {"agent_id": "critical-agent", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert r.paths[0].severity in ("critical", "high")


def test_transcript_events_fallback():
    events = [
        {"agent_id": "a1", "claimed_tool": "modify_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev1", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation(events, [])
    assert r.summary.total_paths == 1
    assert r.paths[0].steps[0].source_file == "transcripts.jsonl"


def test_dedup_across_sources():
    events = [
        {"agent_id": "a1", "claimed_tool": "create_role", "resource": "roles/x",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "c1", "policy_decision": "allowed"},
    ]
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/x",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "c1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation(events, control)
    assert r.summary.total_paths == 1
    assert len(r.paths[0].steps) == 1


def test_is_sensitive_resource():
    assert _is_sensitive_resource("iam/policy.json") is True
    assert _is_sensitive_resource("roles/admin") is True
    assert _is_sensitive_resource("data/users.csv") is False


def test_is_sensitive_effect():
    assert _is_sensitive_effect("role-modified") is True
    assert _is_sensitive_effect("credential-created") is True
    assert _is_sensitive_effect("file-read") is False


def test_is_escalation_tool():
    assert _is_escalation_tool("create_role") is True
    assert _is_escalation_tool("modify_policy") is True
    assert _is_escalation_tool("read_file") is False


def test_classify_step_bypassed():
    assert _classify_step_reason("write", "x", "done", "denied") == "bypassed-policy-denial"


def test_classify_step_tool():
    assert _classify_step_reason("create_role", "roles/x", "", "allowed") == "privilege-tool-invoked"


def test_classify_step_effect():
    assert _classify_step_reason("do_thing", "x", "credential-created", "allowed") == "sensitive-effect-observed"


def test_classify_step_resource():
    assert _classify_step_reason("read", "iam/policy", "file-read", "allowed") == "sensitive-resource-accessed"


def test_classify_step_none():
    assert _classify_step_reason("read_file", "data.txt", "file-read", "allowed") is None


def test_format_text_output():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    text = format_text(r)
    assert "Privilege Escalation" in text
    assert "a1" in text
    assert "PE-001" in text


def test_format_json_output():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "cred-1", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "paths" in data
    assert "summary" in data
    assert data["summary"]["total_paths"] == 1


def test_format_text_empty():
    r = analyze_privilege_escalation([], [])
    text = format_text(r)
    assert "Privilege Escalation" in text
    assert "0" in text


def test_summary_by_severity():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "tool_call_id": "tc1", "credential_id": "", "policy_decision": "allowed"},
        {"agent_id": "a2", "actual_tool": "read_config", "resource": "secret/keys",
         "effect": "file-read", "timestamp": "2025-01-01T00:02:00Z",
         "tool_call_id": "tc2", "credential_id": "", "policy_decision": "allowed"},
    ]
    r = analyze_privilege_escalation([], control)
    assert sum(r.summary.by_severity.values()) == r.summary.total_paths
