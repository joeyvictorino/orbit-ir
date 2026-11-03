"""Tests for privilege chain reconstruction."""
from orbit_ir.privilege_chain import (
    analyze,
    format_text,
    format_json,
    _privilege_level,
    _is_escalation,
    _is_bypass,
    _identify_critical_links,
    ChainLink,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_chains == 0
    assert r.agents_involved == []


def test_no_escalation_events():
    events = [
        {"agent_id": "a1", "claimed_tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z",
         "credential_id": "", "policy_decision": "allowed"},
    ]
    r = analyze(events, [])
    assert r.summary.total_chains == 0


def test_single_escalation_step():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze([], control)
    assert r.summary.total_chains == 1
    assert r.chains[0].chain_length == 1
    assert r.chains[0].initial_privilege == "user"


def test_multi_step_chain():
    control = [
        {"agent_id": "a1", "actual_tool": "assume_role", "resource": "roles/editor",
         "effect": "role-changed", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "viewer"},
        {"agent_id": "a1", "actual_tool": "grant_permission", "resource": "perms/all",
         "effect": "permission-granted", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "editor"},
        {"agent_id": "a1", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "privilege-escalated", "timestamp": "2025-01-01T00:03:00Z",
         "credential_id": "cred-2", "policy_decision": "allowed", "role": "admin"},
    ]
    r = analyze([], control)
    assert r.summary.total_chains == 1
    chain = r.chains[0]
    assert chain.chain_length == 3
    assert chain.initial_privilege == "viewer"
    assert chain.final_privilege == "admin"
    assert "cred-1" in chain.credentials_used
    assert "cred-2" in chain.credentials_used


def test_bypass_detection():
    control = [
        {"agent_id": "a1", "actual_tool": "write_file", "resource": "secret/keys",
         "effect": "secret-written", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "denied", "role": "user"},
    ]
    r = analyze([], control)
    assert r.summary.total_chains == 1
    assert r.chains[0].bypass_count == 1
    assert r.chains[0].severity == "critical"


def test_multiple_agents():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/editor",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "user"},
        {"agent_id": "a2", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "privilege-escalated", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "cred-2", "policy_decision": "allowed", "role": "admin"},
    ]
    r = analyze([], control)
    assert r.summary.total_chains == 2
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_severity_critical_large_jump():
    control = [
        {"agent_id": "a1", "actual_tool": "elevate", "resource": "roles/root",
         "effect": "escalated", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "guest"},
        {"agent_id": "a1", "actual_tool": "create_admin", "resource": "admin/super",
         "effect": "admin-created", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "root"},
    ]
    r = analyze([], control)
    assert r.chains[0].severity == "critical"


def test_severity_medium_small_chain():
    control = [
        {"agent_id": "a1", "actual_tool": "modify_role", "resource": "roles/x",
         "effect": "modified", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze([], control)
    assert r.chains[0].severity in ("low", "medium")


def test_severity_high_multiple_critical_links():
    control = [
        {"agent_id": "a1", "actual_tool": "create_credential", "resource": "creds/x",
         "effect": "cred-created", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "c1", "policy_decision": "allowed", "role": "user"},
        {"agent_id": "a1", "actual_tool": "create_token", "resource": "tokens/y",
         "effect": "token-minted", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "c2", "policy_decision": "allowed", "role": "editor"},
    ]
    r = analyze([], control)
    chain = r.chains[0]
    assert len(chain.critical_links) >= 2
    assert chain.severity in ("high", "critical")


def test_transcript_events():
    events = [
        {"agent_id": "a1", "claimed_tool": "assign_role", "resource": "roles/admin",
         "effect": "role-assigned", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze(events, [])
    assert r.summary.total_chains == 1


def test_chain_ordering_by_severity():
    control = [
        {"agent_id": "low-agent", "actual_tool": "modify_role", "resource": "roles/x",
         "effect": "modified", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "user"},
        {"agent_id": "crit-agent", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "escalated", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "", "policy_decision": "denied", "role": "user"},
    ]
    r = analyze([], control)
    assert r.chains[0].severity == "critical"


def test_privilege_level_known():
    assert _privilege_level("admin") == 6
    assert _privilege_level("root") == 7
    assert _privilege_level("guest") == 1
    assert _privilege_level("none") == 0


def test_privilege_level_unknown():
    assert _privilege_level("custom_role") == 3


def test_is_escalation():
    assert _is_escalation("create_role") is True
    assert _is_escalation("elevate") is True
    assert _is_escalation("read_file") is False
    assert _is_escalation("modify_permissions") is True


def test_is_bypass():
    assert _is_bypass("denied", "secret-written") is True
    assert _is_bypass("allowed", "secret-written") is False
    assert _is_bypass("denied", "") is False
    assert _is_bypass("denied", "none") is False


def test_format_text():
    control = [
        {"agent_id": "a1", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "escalated", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze([], control)
    text = format_text(r)
    assert "Privilege Chain" in text
    assert "a1" in text
    assert "PC-001" in text


def test_format_json():
    control = [
        {"agent_id": "a1", "actual_tool": "create_role", "resource": "roles/admin",
         "effect": "role-modified", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-1", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze([], control)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "chains" in data
    assert "summary" in data
    assert data["summary"]["total_chains"] == 1


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Privilege Chain" in text
    assert "0" in text


def test_summary_stats():
    control = [
        {"agent_id": "a1", "actual_tool": "assume_role", "resource": "roles/editor",
         "effect": "changed", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "viewer"},
        {"agent_id": "a1", "actual_tool": "elevate", "resource": "roles/admin",
         "effect": "escalated", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "admin"},
        {"agent_id": "a2", "actual_tool": "create_role", "resource": "roles/x",
         "effect": "created", "timestamp": "2025-01-01T00:03:00Z",
         "credential_id": "", "policy_decision": "allowed", "role": "user"},
    ]
    r = analyze([], control)
    assert r.summary.total_chains == 2
    assert r.summary.total_links == 3
    assert r.summary.max_chain_length == 2
    assert r.summary.avg_chain_length == 1.5


def test_critical_link_identification():
    link_normal = ChainLink(
        timestamp="t1", agent_id="a", action="modify_role", resource="r",
        effect="e", credential_id="", source_role="user", target_role="editor",
        is_bypass=False, policy_decision="allowed",
    )
    link_bypass = ChainLink(
        timestamp="t2", agent_id="a", action="write", resource="r",
        effect="done", credential_id="", source_role="user", target_role="user",
        is_bypass=True, policy_decision="denied",
    )
    link_big_jump = ChainLink(
        timestamp="t3", agent_id="a", action="elevate", resource="r",
        effect="e", credential_id="", source_role="guest", target_role="admin",
        is_bypass=False, policy_decision="allowed",
    )
    links = [link_normal, link_bypass, link_big_jump]
    critical = _identify_critical_links(links)
    assert 1 in critical  # bypass
    assert 2 in critical  # big jump


def test_credential_tracking():
    control = [
        {"agent_id": "a1", "actual_tool": "create_credential", "resource": "creds/x",
         "effect": "cred-created", "timestamp": "2025-01-01T00:01:00Z",
         "credential_id": "cred-alpha", "policy_decision": "allowed", "role": "user"},
        {"agent_id": "a1", "actual_tool": "create_token", "resource": "tokens/y",
         "effect": "token-minted", "timestamp": "2025-01-01T00:02:00Z",
         "credential_id": "cred-beta", "policy_decision": "allowed", "role": "editor"},
    ]
    r = analyze([], control)
    chain = r.chains[0]
    assert "cred-alpha" in chain.credentials_used
    assert "cred-beta" in chain.credentials_used
