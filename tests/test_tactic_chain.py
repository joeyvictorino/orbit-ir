"""Tests for MITRE ATT&CK tactic chain analysis."""
from orbit_ir.tactic_chain import (
    analyze_tactic_chains,
    format_text,
    format_json,
    _map_tactic,
    _score_completeness,
    _detect_jumps,
    TACTIC_ORDER,
    TACTIC_INDEX,
    TacticEvent,
)


def test_empty_events():
    r = analyze_tactic_chains([])
    assert r.summary.total_chains == 0
    assert r.agents_involved == []
    assert r.all_events == []


def test_no_tactic_events():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.total_chains == 0


def test_single_tactic_event():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "network",
         "effect": "recon-performed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.total_chains == 1
    assert r.chains[0].tactics == ["reconnaissance"]
    assert r.chains[0].length == 1


def test_sequential_chain():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "exploit_vuln", "resource": "srv",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "execute_command", "resource": "host",
         "effect": "", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.total_chains == 1
    chain = r.chains[0]
    assert chain.tactics == ["reconnaissance", "initial-access", "execution"]
    assert chain.length == 3


def test_chain_with_jumps():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "dump_credentials", "resource": "creds",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tactic_chains(events)
    chain = r.chains[0]
    assert len(chain.jumps) == 1
    jump = chain.jumps[0]
    assert jump.from_tactic == "reconnaissance"
    assert jump.to_tactic == "credential-access"
    assert "initial-access" in jump.skipped
    assert "execution" in jump.skipped


def test_no_jumps_for_sequential():
    events = [
        {"agent_id": "a1", "claimed_tool": "execute_command", "resource": "host",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "create_service", "resource": "svc",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.chains[0].jumps == []


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "exfiltrate", "resource": "data",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.total_chains == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_completeness_score():
    assert _score_completeness([]) == 0.0
    assert _score_completeness(["reconnaissance"]) == round(1 / 14, 3)
    all_tactics = list(TACTIC_ORDER)
    assert _score_completeness(all_tactics) == 1.0


def test_completeness_dedup():
    score = _score_completeness(["reconnaissance", "reconnaissance", "execution"])
    assert score == round(2 / 14, 3)


def test_map_tactic_by_tool():
    assert _map_tactic("nmap", "", "") == "reconnaissance"
    assert _map_tactic("execute_command", "", "") == "execution"
    assert _map_tactic("exfiltrate", "", "") == "exfiltration"


def test_map_tactic_by_effect():
    assert _map_tactic("unknown_tool", "recon-performed", "") == "reconnaissance"
    assert _map_tactic("custom_tool", "credential-stolen", "") == "credential-access"


def test_map_tactic_by_hint():
    assert _map_tactic("unknown", "unknown", "discovery") == "discovery"
    assert _map_tactic("nmap", "", "execution") == "execution"


def test_map_tactic_none():
    assert _map_tactic("do_thing", "did_thing", "") is None


def test_map_tactic_substring_match():
    assert _map_tactic("custom_nmap_scanner", "", "") == "reconnaissance"
    assert _map_tactic("tool", "data-exfiltrated-slowly", "") == "exfiltration"


def test_repeated_tactic_collapses():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net1",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "port_scan", "resource": "net2",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "claimed_tool": "execute_command", "resource": "host",
         "effect": "", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_tactic_chains(events)
    chain = r.chains[0]
    assert chain.tactics == ["reconnaissance", "execution"]
    assert len(chain.events) == 3


def test_chains_sorted_by_completeness():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "claimed_tool": "exploit_vuln", "resource": "srv",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "claimed_tool": "execute_command", "resource": "host",
         "effect": "", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.chains[0].agent_id == "a2"
    assert r.chains[0].completeness > r.chains[1].completeness


def test_tactic_distribution():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "port_scan", "resource": "net2",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.by_tactic.get("reconnaissance", 0) == 2


def test_format_text_output():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "claimed_tool": "execute_command", "resource": "host",
         "effect": "", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_tactic_chains(events)
    text = format_text(r)
    assert "Tactic Chain Analysis" in text
    assert "TC-001" in text
    assert "reconnaissance" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tactic_chains(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "chains" in data
    assert "summary" in data
    assert data["summary"]["total_chains"] == 1


def test_format_text_empty():
    r = analyze_tactic_chains([])
    text = format_text(r)
    assert "Tactic Chain Analysis" in text
    assert "0" in text


def test_format_json_empty():
    r = analyze_tactic_chains([])
    import json
    data = json.loads(format_json(r))
    assert data["chains"] == []
    assert data["summary"]["total_chains"] == 0


def test_full_kill_chain():
    tools = ["nmap", "register_domain", "exploit_vuln", "execute_command",
             "install_backdoor", "elevate", "clear_logs", "dump_credentials",
             "whoami", "psexec", "collect_data", "exfiltrate", "beacon", "encrypt_data"]
    events = [
        {"agent_id": "a1", "claimed_tool": t, "resource": f"r{i}",
         "effect": "", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i, t in enumerate(tools)
    ]
    r = analyze_tactic_chains(events)
    assert r.chains[0].completeness == 1.0
    assert r.chains[0].length == 14


def test_detect_jumps_direct():
    tactics = ["reconnaissance", "lateral-movement"]
    events = [
        TacticEvent("t1", "a1", "reconnaissance", "nmap", "", "r1", "f", 1),
        TacticEvent("t2", "a1", "lateral-movement", "psexec", "", "r2", "f", 2),
    ]
    jumps = _detect_jumps(tactics, "a1", events)
    assert len(jumps) == 1
    assert "initial-access" in jumps[0].skipped


def test_actual_tool_fallback():
    events = [
        {"agent_id": "a1", "actual_tool": "nmap", "resource": "net",
         "effect": "", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.summary.total_chains == 1
    assert r.chains[0].tactics == ["reconnaissance"]


def test_tactic_hint_overrides():
    events = [
        {"agent_id": "a1", "claimed_tool": "nmap", "resource": "net",
         "effect": "", "tactic": "impact", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_tactic_chains(events)
    assert r.chains[0].tactics == ["impact"]
