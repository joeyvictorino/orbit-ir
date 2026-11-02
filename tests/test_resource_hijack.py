from orbit_ir.resource_hijack import (
    analyze,
    format_text,
    format_json,
    _detect_cryptomining,
    _detect_ddos,
    _detect_resource_exhaustion,
    _detect_unauthorized_compute,
    _detect_bandwidth_abuse,
    _detect_quota_theft,
    _classify_severity,
)
import json


def test_analyze_empty():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []


def test_detect_cryptomining():
    ev = {"content": "Starting xmrig miner on pool stratum+tcp://pool.example.com"}
    found, matches, evidence = _detect_cryptomining(ev)
    assert found
    assert "miner" in matches
    assert "xmrig" in matches
    assert "Cryptomining" in evidence


def test_detect_cryptomining_in_args():
    ev = {"content": "", "args": {"command": "start mining bitcoin"}}
    found, matches, _ = _detect_cryptomining(ev)
    assert found
    assert "mining" in matches


def test_detect_ddos():
    ev = {"content": "Launching syn flood attack against target"}
    found, matches, evidence = _detect_ddos(ev)
    assert found
    assert "flood" in matches


def test_detect_resource_exhaustion():
    ev = {"content": "Process triggered oom killer", "error": "out of memory"}
    found, matches, _ = _detect_resource_exhaustion(ev)
    assert found
    assert "oom" in matches
    assert "out of memory" in matches


def test_detect_unauthorized_compute():
    ev = {"content": "Started hidden service on port 8080"}
    found, matches, _ = _detect_unauthorized_compute(ev)
    assert found
    assert "hidden service" in matches


def test_detect_bandwidth_abuse():
    ev = {"bytes_sent": 200_000_000, "connection_count": 1500}
    found, matches, _ = _detect_bandwidth_abuse(ev)
    assert found
    assert len(matches) == 2


def test_detect_bandwidth_normal():
    ev = {"bytes_sent": 1000, "connection_count": 5}
    found, _, _ = _detect_bandwidth_abuse(ev)
    assert not found


def test_detect_quota_theft():
    ev = {"tokens_used": 1_000_000, "unauthorized_model": "gpt-4"}
    found, matches, _ = _detect_quota_theft(ev)
    assert found
    assert len(matches) == 2


def test_classify_severity_critical():
    assert _classify_severity("cryptomining", ["a", "b"]) == "critical"
    assert _classify_severity("ddos-participation", ["a"]) == "critical"


def test_classify_severity_high():
    assert _classify_severity("unauthorized-compute", ["a"]) == "high"
    assert _classify_severity("resource-exhaustion", ["a", "b", "c"]) == "high"


def test_analyze_mixed_events():
    events = [
        {"agent_id": "agent-1", "timestamp": "2024-01-01T00:00:00Z",
         "event_id": "e1", "content": "Starting xmrig miner"},
        {"agent_id": "agent-2", "timestamp": "2024-01-01T00:01:00Z",
         "event_id": "e2", "content": "Launching syn flood against target"},
    ]
    control = [
        {"agent_id": "agent-1", "timestamp": "2024-01-01T00:02:00Z",
         "event_id": "c1", "content": "fork bomb detected", "error": "out of memory"},
    ]
    r = analyze(events, control)
    assert r.summary.total_patterns >= 3
    assert r.summary.agents_hijacking == 2
    assert "agent-1" in r.agents_involved
    assert "agent-2" in r.agents_involved


def test_dedup():
    events = [
        {"agent_id": "a", "event_id": "e1", "content": "xmrig miner pool", "timestamp": ""},
        {"agent_id": "a", "event_id": "e1", "content": "xmrig miner pool", "timestamp": ""},
    ]
    r = analyze(events)
    crypto_patterns = [p for p in r.patterns if p.hijack_type == "cryptomining"]
    assert len(crypto_patterns) == 1


def test_format_text():
    events = [
        {"agent_id": "agent-1", "timestamp": "t1", "event_id": "e1",
         "content": "mining bitcoin crypto", "resource": "gpu-cluster"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Resource Hijacking" in text
    assert "agent-1" in text
    assert "cryptomining" in text


def test_format_text_empty():
    r = analyze([])
    text = format_text(r)
    assert "Resource Hijacking" in text
    assert "Total patterns:       0" in text


def test_format_json():
    events = [
        {"agent_id": "a", "timestamp": "t1", "event_id": "e1",
         "content": "xmrig miner"},
    ]
    r = analyze(events)
    out = format_json(r)
    parsed = json.loads(out)
    assert len(parsed["patterns"]) >= 1
    assert "summary" in parsed


def test_resource_map():
    events = [
        {"agent_id": "a", "timestamp": "t1", "event_id": "e1",
         "content": "xmrig miner", "resource": "gpu-0"},
        {"agent_id": "b", "timestamp": "t2", "event_id": "e2",
         "content": "mining bitcoin", "resource": "gpu-0"},
    ]
    r = analyze(events)
    assert "gpu-0" in r.resource_map
    assert "a" in r.resource_map["gpu-0"]
    assert "b" in r.resource_map["gpu-0"]


def test_no_false_positive():
    ev = {"content": "The weather is nice today", "agent_id": "a", "event_id": "e1"}
    r = analyze([ev])
    assert r.summary.total_patterns == 0
