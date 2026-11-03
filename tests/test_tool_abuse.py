from orbit_ir.tool_abuse import (
    analyze_tool_abuse,
    format_text,
    format_json,
    _load_events,
    _has_injection,
    _is_privilege_tool,
    _is_destructive_tool,
    _is_recon_tool,
)


def test_empty_events():
    r = analyze_tool_abuse([])
    assert r.summary.total_detections == 0
    assert r.summary.agents_involved == 0


def test_no_abuse():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z"},
    ]
    r = analyze_tool_abuse(events)
    assert r.summary.total_detections == 0


def test_scope_violation():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z",
         "declared_capabilities": ["write_file"]},
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z",
         "declared_capabilities": ["write_file"]},
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "scope-violation"]
    assert len(found) == 1
    assert found[0].tool == "read_file"


def test_excessive_frequency():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": f"2026-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "excessive-frequency"]
    assert len(found) == 1
    assert found[0].confidence in ("high", "medium")


def test_unauthorized_chain():
    events = [
        {"agent_id": "a1", "tool": "list_directory", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "sudo", "timestamp": "2026-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "delete_file", "timestamp": "2026-01-01T00:02:00Z"},
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "unauthorized-chain"]
    assert len(found) >= 1
    assert found[0].confidence == "high"


def test_parameter_injection():
    events = [
        {"agent_id": "a1", "tool": "exec_cmd", "timestamp": "2026-01-01T00:00:00Z",
         "parameters": {"cmd": "echo hello; rm -rf /"}},
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "parameter-injection"]
    assert len(found) == 1
    assert found[0].confidence == "high"


def test_privilege_escalation_tool():
    events = [
        {"agent_id": "a1", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "privilege-escalation-tool"]
    assert len(found) == 1


def test_shadow_tool():
    events = [
        {"agent_id": "a1", "claimed_tool": "read_file", "actual_tool": "exec_cmd",
         "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    found = [d for d in r.detections if d.category == "shadow-tool"]
    assert len(found) == 1
    assert found[0].confidence == "high"


def test_agent_profiles():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    assert len(r.agent_profiles) == 2
    a1_profile = [p for p in r.agent_profiles if p.agent_id == "a1"][0]
    assert a1_profile.total_calls == 2
    assert a1_profile.unique_tools == 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "claimed_tool": "safe", "actual_tool": "dangerous",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a2", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    assert r.summary.agents_involved == 2


def test_has_injection():
    assert _has_injection({"cmd": "echo; rm -rf /"})
    assert _has_injection({"q": "' OR 1=1"})
    assert _has_injection({"x": "${HOME}"})
    assert not _has_injection({"cmd": "echo hello"})
    assert not _has_injection({})


def test_is_privilege_tool():
    assert _is_privilege_tool("sudo")
    assert _is_privilege_tool("elevate")
    assert _is_privilege_tool("grant_access")
    assert not _is_privilege_tool("read_file")


def test_is_destructive_tool():
    assert _is_destructive_tool("delete_file")
    assert _is_destructive_tool("drop_table")
    assert not _is_destructive_tool("read_file")


def test_is_recon_tool():
    assert _is_recon_tool("list_directory")
    assert _is_recon_tool("scan_ports")
    assert not _is_recon_tool("write_file")


def test_timeline_ordering():
    events = [
        {"agent_id": "a1", "claimed_tool": "a", "actual_tool": "b",
         "timestamp": "2026-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "c", "actual_tool": "d",
         "timestamp": "2026-01-01T00:01:00Z"},
    ]
    r = analyze_tool_abuse(events)
    if len(r.timeline) >= 2:
        assert r.timeline[0]["timestamp"] <= r.timeline[1]["timestamp"]


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    text = format_text(r)
    assert "Tool Abuse Detection Report" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    j = format_json(r)
    assert '"detections"' in j
    assert '"summary"' in j


def test_skip_empty_agent():
    events = [
        {"agent_id": "", "tool": "sudo", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    assert r.summary.total_detections == 0


def test_mitre_technique_assigned():
    events = [
        {"agent_id": "a1", "claimed_tool": "read_file", "actual_tool": "exec_cmd",
         "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_tool_abuse(events)
    assert r.detections[0].mitre_technique == "T1036"
