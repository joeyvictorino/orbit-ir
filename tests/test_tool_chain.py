"""Tests for tool_chain module."""
from orbit_ir.tool_chain import analyze_tool_chains, format_text, format_json


def _ev(ts: str, agent: str = "agent-1", tool: str = "read_file") -> dict:
    return {"timestamp": ts, "agent": agent, "tool": tool}


def test_empty():
    r = analyze_tool_chains([])
    assert r.summary.total_chains == 0
    assert r.summary.total_tool_calls == 0


def test_single_chain():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="ls"),
        _ev("2025-01-01T00:00:05Z", tool="cat"),
        _ev("2025-01-01T00:00:10Z", tool="grep"),
    ]
    r = analyze_tool_chains(events)
    assert r.summary.total_chains == 1
    assert r.chains[0].length == 3
    assert r.chains[0].tools == ["ls", "cat", "grep"]


def test_two_chains_by_gap():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="ls"),
        _ev("2025-01-01T00:00:05Z", tool="cat"),
        _ev("2025-01-01T00:05:00Z", tool="find"),
    ]
    r = analyze_tool_chains(events, chain_gap_seconds=120)
    assert r.summary.total_chains == 2


def test_escalation_detection():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="read_file"),
        _ev("2025-01-01T00:00:05Z", tool="sudo"),
    ]
    r = analyze_tool_chains(events)
    assert r.chains[0].has_escalation is True


def test_exfil_detection():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="cat"),
        _ev("2025-01-01T00:00:05Z", tool="curl"),
    ]
    r = analyze_tool_chains(events)
    assert r.chains[0].has_exfil_pattern is True


def test_transitions():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="ls"),
        _ev("2025-01-01T00:00:05Z", tool="cat"),
        _ev("2025-01-01T00:00:10Z", tool="ls"),
        _ev("2025-01-01T00:00:15Z", tool="cat"),
    ]
    r = analyze_tool_chains(events)
    trans_map = {(t.from_tool, t.to_tool): t.count for t in r.transitions}
    assert trans_map[("ls", "cat")] == 2


def test_suspicious_recon_to_escalation():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="ls"),
        _ev("2025-01-01T00:00:05Z", tool="find"),
        _ev("2025-01-01T00:00:10Z", tool="sudo"),
    ]
    r = analyze_tool_chains(events)
    assert r.summary.suspicious_chains >= 1
    assert any("recon-to-escalation" in s.reason for s in r.suspicious)


def test_suspicious_escalation_exfil():
    events = [
        _ev("2025-01-01T00:00:00Z", tool="chmod"),
        _ev("2025-01-01T00:00:05Z", tool="curl"),
    ]
    r = analyze_tool_chains(events)
    assert any("escalation-with-exfiltration" in s.reason for s in r.suspicious)


def test_multi_agent():
    events = [
        _ev("2025-01-01T00:00:00Z", agent="a1", tool="ls"),
        _ev("2025-01-01T00:00:05Z", agent="a2", tool="cat"),
    ]
    r = analyze_tool_chains(events)
    assert r.summary.agents_analyzed == 2
    assert r.summary.total_chains == 2


def test_format_text_header():
    r = analyze_tool_chains([])
    out = format_text(r)
    assert "Tool Chain Analysis" in out


def test_format_json():
    events = [_ev("2025-01-01T00:00:00Z", tool="ls")]
    r = analyze_tool_chains(events)
    out = format_json(r)
    assert '"total_chains"' in out
    assert '"chains"' in out


def test_no_tool_events_skipped():
    events = [{"timestamp": "2025-01-01T00:00:00Z", "agent": "a1"}]
    r = analyze_tool_chains(events)
    assert r.summary.total_tool_calls == 0
