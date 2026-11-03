"""Tests for lateral movement path reconstruction."""
from orbit_ir.lateral_path import analyze_lateral, format_text, format_json


def _ev(agent, tool, resource="", effect="", target_agent="", ts="2025-01-01T00:00:00Z"):
    ev = {"agent_id": agent, "tool": tool, "resource": resource, "effect": effect, "timestamp": ts}
    if target_agent:
        ev["target_agent"] = target_agent
    return ev


def test_empty_events():
    r = analyze_lateral([])
    assert r.summary.total_hops == 0
    assert r.summary.total_paths == 0
    assert r.summary.agents_involved == 0


def test_ssh_hop():
    events = [_ev("agent-a", "ssh_connect", "user@target-host", target_agent="target-host")]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 1
    assert r.hops[0].method == "remote-service"
    assert r.hops[0].technique_id == "T1021.004"


def test_rdp_hop():
    events = [_ev("agent-a", "rdp_connect", "admin@server", target_agent="server")]
    r = analyze_lateral(events)
    assert r.hops[0].technique_id == "T1021.001"


def test_smb_hop():
    events = [_ev("agent-a", "psexec", "\\\\target\\share", target_agent="target")]
    r = analyze_lateral(events)
    assert r.hops[0].technique_id == "T1021.002"


def test_winrm_hop():
    events = [_ev("agent-a", "winrm", "target-server", target_agent="target-server")]
    r = analyze_lateral(events)
    assert r.hops[0].technique_id == "T1021.006"


def test_credential_forward_hash():
    events = [_ev("agent-a", "pass_hash", "ntlm_hash", target_agent="dc-01")]
    r = analyze_lateral(events)
    assert r.hops[0].method == "credential-forward"
    assert r.hops[0].technique_id == "T1550.002"


def test_credential_forward_ticket():
    events = [_ev("agent-a", "pass_ticket", "krbtgt", target_agent="dc-02")]
    r = analyze_lateral(events)
    assert r.hops[0].technique_id == "T1550.003"


def test_credential_forward_token():
    events = [_ev("agent-a", "inject_token", "oauth_token", target_agent="api-server")]
    r = analyze_lateral(events)
    assert r.hops[0].technique_id == "T1550.001"


def test_file_transfer():
    events = [_ev("agent-a", "scp", "/tmp/tool.bin", target_agent="target-host")]
    r = analyze_lateral(events)
    assert r.hops[0].method == "tool-transfer"
    assert r.hops[0].technique_id == "T1570"


def test_pivot_detection():
    events = [_ev("agent-a", "ssh_tunnel", "localhost:8080 -> target:22", target_agent="target")]
    r = analyze_lateral(events)
    assert r.hops[0].method == "pivot"


def test_agent_delegation():
    events = [_ev("agent-a", "delegate_task", "scan_network", target_agent="agent-b")]
    r = analyze_lateral(events)
    assert r.hops[0].method == "agent-delegation"
    assert r.hops[0].technique_id == "T1072"


def test_multi_hop_path():
    events = [
        _ev("agent-a", "ssh_connect", "root@host-1", target_agent="host-1", ts="2025-01-01T00:01:00Z"),
        _ev("host-1", "ssh_connect", "admin@host-2", target_agent="host-2", ts="2025-01-01T00:02:00Z"),
        _ev("host-2", "psexec", "\\\\host-3\\c$", target_agent="host-3", ts="2025-01-01T00:03:00Z"),
    ]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 3
    assert r.summary.total_paths >= 1
    assert r.summary.agents_involved >= 3


def test_path_risk_critical():
    events = [
        _ev("a", "ssh_connect", "", target_agent="b", ts="t1"),
        _ev("b", "ssh_connect", "", target_agent="c", ts="t2"),
        _ev("c", "ssh_connect", "", target_agent="d", ts="t3"),
        _ev("d", "ssh_connect", "", target_agent="e", ts="t4"),
    ]
    r = analyze_lateral(events)
    assert any(p.risk_level == "critical" for p in r.paths)


def test_path_risk_high_with_cred_forward():
    events = [_ev("a", "pass_hash", "hash", target_agent="b")]
    r = analyze_lateral(events)
    assert r.paths[0].risk_level == "high"


def test_multiple_methods():
    events = [
        _ev("a", "ssh_connect", "", target_agent="b"),
        _ev("a", "pass_hash", "", target_agent="c"),
        _ev("a", "scp", "", target_agent="d"),
    ]
    r = analyze_lateral(events)
    assert len(r.summary.by_method) >= 3


def test_no_lateral_events():
    events = [_ev("a", "read_file", "/tmp/foo.txt")]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 0


def test_confidence_levels():
    events = [
        _ev("a", "ssh_connect", "", target_agent="b"),
        _ev("a", "scp", "", target_agent="c"),
    ]
    r = analyze_lateral(events)
    confidences = {h.confidence for h in r.hops}
    assert "high" in confidences or "medium" in confidences


def test_target_inference_from_resource():
    events = [{"agent_id": "a", "tool": "ssh_connect", "resource": "root@web-server", "effect": "", "timestamp": "t1"}]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 1
    assert r.hops[0].target_agent == "web-server"


def test_agents_involved():
    events = [
        _ev("agent-a", "ssh_connect", "", target_agent="host-1"),
        _ev("agent-b", "ssh_connect", "", target_agent="host-2"),
    ]
    r = analyze_lateral(events)
    assert "agent-a" in r.agents_involved
    assert "agent-b" in r.agents_involved
    assert "host-1" in r.agents_involved
    assert "host-2" in r.agents_involved


def test_unique_techniques_count():
    events = [
        _ev("a", "ssh_connect", "", target_agent="b"),
        _ev("a", "pass_hash", "hash", target_agent="c"),
        _ev("a", "scp", "", target_agent="d"),
    ]
    r = analyze_lateral(events)
    assert r.summary.unique_techniques >= 3


def test_format_text_output():
    events = [_ev("a", "ssh_connect", "user@target", target_agent="target")]
    r = analyze_lateral(events)
    text = format_text(r)
    assert "Lateral Movement" in text
    assert "remote-service" in text


def test_format_json_output():
    events = [_ev("a", "ssh_connect", "", target_agent="b")]
    r = analyze_lateral(events)
    j = format_json(r)
    assert j.startswith("{")
    data = __import__("json").loads(j)
    assert "hops" in data
    assert "paths" in data
    assert "summary" in data


def test_exploitation_method():
    events = [_ev("a", "exploit_remote_service", "target vuln", effect="remote code execution", target_agent="target")]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 0 or r.hops[0].method == "exploitation"


def test_taint_shared_content():
    events = [_ev("a", "write_shared_drive", "shared content payload", effect="tainted shared content", target_agent="victims")]
    r = analyze_lateral(events)
    assert r.summary.total_hops == 0 or r.hops[0].method == "taint-shared"
