"""Tests for resource abuse pattern detection."""
from orbit_ir.resource_abuse import (
    analyze,
    format_text,
    format_json,
    _parse_timestamp,
    _detect_excessive_api,
    _detect_storage_abuse,
    _detect_compute_hijacking,
    _detect_bandwidth_abuse,
    AbusePattern,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []


def test_no_abuse():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "read_file", "resource": "data2.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze(events)
    assert r.summary.total_patterns == 0


def test_excessive_api_calls():
    events = [
        {"agent_id": "a1", "tool": "api_call", "resource": "endpoint",
         "effect": "called", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(15)
    ]
    r = analyze(events, api_threshold=10, window_seconds=60.0)
    assert r.summary.total_patterns >= 1
    assert any(p.abuse_type == "excessive-api-calls" for p in r.patterns)


def test_excessive_api_below_threshold():
    events = [
        {"agent_id": "a1", "tool": "api_call", "resource": "endpoint",
         "effect": "called", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze(events, api_threshold=10)
    assert not any(p.abuse_type == "excessive-api-calls" for p in r.patterns)


def test_storage_abuse_by_bytes():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": f"file{i}.dat",
         "effect": "written", "timestamp": f"2025-01-01T00:00:{i:02d}Z",
         "bytes": 200_000}
        for i in range(10)
    ]
    r = analyze(events, storage_threshold=1_000_000)
    assert any(p.abuse_type == "storage-quota-abuse" for p in r.patterns)


def test_storage_abuse_by_count():
    events = [
        {"agent_id": "a1", "tool": "upload", "resource": f"file{i}.dat",
         "effect": "uploaded", "timestamp": f"2025-01-01T00:00:{i:02d}Z",
         "bytes": 100}
        for i in range(25)
    ]
    r = analyze(events, storage_threshold=100_000_000)
    assert any(p.abuse_type == "storage-quota-abuse" for p in r.patterns)


def test_no_storage_abuse():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "file.dat",
         "effect": "written", "timestamp": "2025-01-01T00:00:00Z",
         "bytes": 100}
    ]
    r = analyze(events, storage_threshold=1_000_000)
    assert not any(p.abuse_type == "storage-quota-abuse" for p in r.patterns)


def test_compute_hijacking():
    events = [
        {"agent_id": "a1", "tool": "run_mining_script", "resource": "crypto_miner",
         "effect": "hash-computed", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "gpu_benchmark", "resource": "compute_node",
         "effect": "benchmark-run", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze(events)
    assert any(p.abuse_type == "compute-hijacking" for p in r.patterns)


def test_no_compute_hijacking():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    assert not any(p.abuse_type == "compute-hijacking" for p in r.patterns)


def test_bandwidth_abuse():
    events = [
        {"agent_id": "a1", "tool": "send_data", "resource": "remote_server",
         "effect": "transfer-complete", "timestamp": f"2025-01-01T00:00:{i:02d}Z",
         "bytes": 1_000_000}
        for i in range(10)
    ]
    r = analyze(events, bandwidth_threshold=5_000_000)
    assert any(p.abuse_type == "bandwidth-abuse" for p in r.patterns)


def test_no_bandwidth_abuse():
    events = [
        {"agent_id": "a1", "tool": "send_data", "resource": "server",
         "effect": "transfer-complete", "timestamp": "2025-01-01T00:00:00Z",
         "bytes": 1000}
    ]
    r = analyze(events, bandwidth_threshold=5_000_000)
    assert not any(p.abuse_type == "bandwidth-abuse" for p in r.patterns)


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "run_miner", "resource": "crypto",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "tool": "gpu_crack", "resource": "passwords",
         "effect": "brute-force", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze(events)
    assert r.summary.agents_abusing >= 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_severity_ordering():
    events = []
    for i in range(30):
        events.append(
            {"agent_id": "api-agent", "tool": "api_call", "resource": "ep",
             "effect": "called", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        )
    events.append(
        {"agent_id": "mine-agent", "tool": "crypto_mine", "resource": "gpu",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"}
    )
    r = analyze(events, api_threshold=10)
    severities = [p.severity for p in r.patterns]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(len(severities) - 1):
        assert order.get(severities[i], 4) <= order.get(severities[i + 1], 4)


def test_pattern_ids_assigned():
    events = [
        {"agent_id": "a1", "tool": "run_miner", "resource": "crypto",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    for p in r.patterns:
        assert p.pattern_id.startswith("RA-")


def test_parse_timestamp():
    assert _parse_timestamp("2025-01-01T00:00:00Z") > 0
    assert _parse_timestamp("invalid") == 0.0
    assert _parse_timestamp("") == 0.0


def test_format_text():
    events = [
        {"agent_id": "a1", "tool": "crypto_mine", "resource": "gpu",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Resource Abuse" in text
    assert "a1" in text
    assert "RA-001" in text


def test_format_json():
    events = [
        {"agent_id": "a1", "tool": "crypto_mine", "resource": "gpu",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "patterns" in data
    assert "summary" in data
    assert data["summary"]["total_patterns"] >= 1


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Resource Abuse" in text
    assert "0" in text


def test_summary_by_type():
    events = [
        {"agent_id": "a1", "tool": "run_miner", "resource": "crypto",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    for i in range(15):
        events.append(
            {"agent_id": "a1", "tool": "api_call", "resource": "ep",
             "effect": "called", "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        )
    r = analyze(events, api_threshold=10)
    assert "compute-hijacking" in r.summary.by_type
    if "excessive-api-calls" in r.summary.by_type:
        assert r.summary.by_type["excessive-api-calls"] >= 1


def test_control_events():
    control = [
        {"agent_id": "a1", "actual_tool": "crypto_mine", "resource": "gpu",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze([], control)
    assert r.summary.total_patterns >= 1


def test_confidence_range():
    events = [
        {"agent_id": "a1", "tool": "run_miner", "resource": "crypto",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    for p in r.patterns:
        assert 0.0 <= p.confidence <= 1.0


def test_agent_summary():
    events = [
        {"agent_id": "a1", "tool": "crypto_mine", "resource": "gpu",
         "effect": "mining", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    assert len(r.agent_summaries) == 1
    s = r.agent_summaries[0]
    assert s.agent_id == "a1"
    assert s.total_events >= 1
    assert "compute-hijacking" in s.abuse_types
