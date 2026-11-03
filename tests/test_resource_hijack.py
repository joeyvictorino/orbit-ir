"""Tests for resource hijacking detection."""
import json

from orbit_ir.resource_hijack import (
    analyze,
    format_text,
    format_json,
    _load_events,
    _match_keywords,
    _classify_severity,
    CRYPTO_KEYWORDS,
    DDOS_KEYWORDS,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []
    assert r.resource_map == {}


def test_no_patterns():
    events = [
        {"agent_id": "a1", "content": "reading data file", "timestamp": "2025-01-01T00:00:00Z",
         "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns == 0


def test_cryptomining_detection():
    events = [
        {"agent_id": "a1", "content": "Starting xmrig miner to mine monero with high hashrate",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "resource": "gpu-cluster"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns >= 1
    assert any(p.hijack_type == "cryptomining" for p in r.patterns)
    crypto_p = [p for p in r.patterns if p.hijack_type == "cryptomining"][0]
    assert crypto_p.severity == "critical"


def test_cryptomining_via_args():
    events = [
        {"agent_id": "a1", "content": "executing task",
         "args": {"command": "xmrig --pool stratum+tcp://pool.example.com"},
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "cryptomining" for p in r.patterns)


def test_ddos_detection():
    events = [
        {"agent_id": "a1", "content": "Launching syn flood ddos attack with botnet amplification",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "resource": "network"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "ddos-participation" for p in r.patterns)
    ddos_p = [p for p in r.patterns if p.hijack_type == "ddos-participation"][0]
    assert ddos_p.severity == "critical"


def test_resource_exhaustion():
    events = [
        {"agent_id": "a1", "content": "process caused oom out of memory and cpu spike",
         "error": "resource limit exceeded",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "resource-exhaustion" for p in r.patterns)


def test_unauthorized_compute():
    events = [
        {"agent_id": "a1", "content": "launching hidden service via reverse shell",
         "tool": "unauthorized process spawner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "unauthorized-compute" for p in r.patterns)
    uc_p = [p for p in r.patterns if p.hijack_type == "unauthorized-compute"][0]
    assert uc_p.severity == "high"


def test_bandwidth_abuse():
    events = [
        {"agent_id": "a1", "content": "transferring data",
         "bytes_sent": 200_000_000, "connection_count": 2000,
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "bandwidth-abuse" for p in r.patterns)


def test_bandwidth_no_trigger_under_threshold():
    events = [
        {"agent_id": "a1", "content": "normal transfer",
         "bytes_sent": 1000, "connection_count": 5,
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert not any(p.hijack_type == "bandwidth-abuse" for p in r.patterns)


def test_quota_theft():
    events = [
        {"agent_id": "a1", "content": "using api",
         "tokens_used": 1_000_000, "api_call_count": 200,
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "quota-theft" for p in r.patterns)


def test_quota_theft_unauthorized_model():
    events = [
        {"agent_id": "a1", "content": "generating response",
         "unauthorized_model": "gpt-4-turbo",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.hijack_type == "quota-theft" for p in r.patterns)


def test_multiple_types_same_event():
    events = [
        {"agent_id": "a1",
         "content": "starting xmrig miner for ddos flood with botnet",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    types = {p.hijack_type for p in r.patterns}
    assert len(types) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "launching ddos flood attack",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    assert r.summary.agents_hijacking >= 2


def test_dedup_across_sources():
    events = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    control = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, control)
    crypto_patterns = [p for p in r.patterns if p.hijack_type == "cryptomining"
                       and p.agent_id == "a1" and p.event_id == "tc1"]
    assert len(crypto_patterns) == 1


def test_severity_critical_crypto():
    assert _classify_severity("cryptomining", ["mine"]) == "critical"
    assert _classify_severity("ddos-participation", ["flood"]) == "critical"


def test_severity_high_unauth():
    assert _classify_severity("unauthorized-compute", ["rogue process"]) == "high"


def test_severity_high_many_matches():
    assert _classify_severity("resource-exhaustion", ["a", "b", "c"]) == "high"


def test_severity_medium():
    assert _classify_severity("bandwidth-abuse", ["x", "y"]) == "medium"


def test_resource_map():
    events = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "resource": "gpu-0"},
        {"agent_id": "a2", "content": "mining monero coins",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2",
         "resource": "gpu-0"},
    ]
    r = analyze(events, [])
    assert "gpu-0" in r.resource_map
    assert "a1" in r.resource_map["gpu-0"]
    assert "a2" in r.resource_map["gpu-0"]


def test_source_file_tracking():
    control = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    events = [
        {"agent_id": "a2", "content": "launching ddos flood",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, control)
    sources = {p.source_file for p in r.patterns}
    assert "control_plane.jsonl" in sources
    assert "transcripts.jsonl" in sources


def test_sorted_by_severity():
    events = [
        {"agent_id": "a1", "content": "resource limit exceeded oom",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "xmrig miner started for mining",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    if len(r.patterns) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2}
        for i in range(len(r.patterns) - 1):
            assert sev_order.get(r.patterns[i].severity, 3) <= sev_order.get(r.patterns[i + 1].severity, 3)


def test_format_text_output():
    events = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "resource": "gpu-cluster"},
    ]
    r = analyze(events, [])
    text = format_text(r)
    assert "Resource Hijacking" in text
    assert "a1" in text
    assert "gpu-cluster" in text


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Resource Hijacking" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "content": "starting xmrig miner",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    out = format_json(r)
    data = json.loads(out)
    assert "patterns" in data
    assert "summary" in data
    assert "resource_map" in data


def test_load_events(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"agent_id": "a1", "content": "test"}\n{"agent_id": "a2"}\n')
    events = _load_events(p)
    assert len(events) == 2


def test_load_events_missing():
    events = _load_events("/nonexistent/path.jsonl")
    assert events == []


def test_match_keywords():
    matches = _match_keywords("xmrig mining pool hashrate", CRYPTO_KEYWORDS)
    assert "xmrig" in matches
    assert "mining" in matches
    assert "pool" in matches
