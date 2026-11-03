"""Tests for command-and-control communication detection."""
from orbit_ir.c2_detect import (
    analyze_c2,
    format_text,
    format_json,
    _is_network_tool,
    _is_command_tool,
    _is_beacon_like,
    _has_encoding_indicator,
    _compute_intervals,
    _regularity_score,
)


def test_empty_events():
    r = analyze_c2([])
    assert r.summary.total_beacon_detections == 0
    assert r.summary.total_command_patterns == 0
    assert r.agents_involved == []


def test_no_c2_normal_activity():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "write_file", "resource": "output.txt",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_beacon_detections == 0
    assert r.summary.total_command_patterns == 0


def test_regular_beacon_detection():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.example.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(5)
    ]
    r = analyze_c2(events)
    assert r.summary.total_beacon_detections >= 1
    b = r.beacon_detections[0]
    assert b.regularity_score >= 0.8
    assert b.confidence == "high"


def test_irregular_calls_low_regularity():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com/data",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com/data",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com/data",
         "timestamp": "2025-01-01T00:30:00Z"},
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com/data",
         "timestamp": "2025-01-01T00:31:00Z"},
    ]
    r = analyze_c2(events)
    if r.beacon_detections:
        assert r.beacon_detections[0].regularity_score < 0.8


def test_command_response_pattern():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.com/cmd",
         "direction": "inbound", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "execute", "resource": "task-1",
         "timestamp": "2025-01-01T00:00:10Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.com/result",
         "direction": "outbound", "timestamp": "2025-01-01T00:00:20Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_command_patterns >= 1
    cp = r.command_patterns[0]
    assert cp.pattern_type == "command-response"
    assert cp.confidence == "high"


def test_command_without_report():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.com/cmd",
         "direction": "inbound", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "run_command", "resource": "whoami",
         "timestamp": "2025-01-01T00:00:10Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_command_patterns >= 1
    cp = r.command_patterns[0]
    assert cp.pattern_type == "command-execute"
    assert cp.confidence == "medium"


def test_communication_channels():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com",
         "direction": "outbound", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.example.com",
         "direction": "outbound", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://api.example.com",
         "direction": "inbound", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_channels >= 1
    ch = r.communication_channels[0]
    assert ch.direction == "bidirectional"
    assert ch.event_count == 3


def test_encoding_in_channel():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.com/data",
         "payload": "base64encoded_data", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.com/data",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_channels >= 1
    ch = r.communication_channels[0]
    assert ch.has_encoding is True


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2-1.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(4)
    ] + [
        {"agent_id": "a2", "tool": "http_get", "resource": "https://c2-2.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(4)
    ]
    r = analyze_c2(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_is_network_tool():
    assert _is_network_tool("http_get") is True
    assert _is_network_tool("http_post") is True
    assert _is_network_tool("api_call") is True
    assert _is_network_tool("fetch_url") is True
    assert _is_network_tool("read_file") is False


def test_is_command_tool():
    assert _is_command_tool("execute") is True
    assert _is_command_tool("run_command") is True
    assert _is_command_tool("shell") is True
    assert _is_command_tool("read_file") is False


def test_is_beacon_like():
    assert _is_beacon_like("heartbeat", "") is True
    assert _is_beacon_like("poll", "endpoint") is True
    assert _is_beacon_like("http_get", "beacon_endpoint") is True
    assert _is_beacon_like("read_file", "data.txt") is False


def test_has_encoding_indicator():
    assert _has_encoding_indicator({"tool": "base64_encode"}) is True
    assert _has_encoding_indicator({"payload": "base64_data"}) is True
    assert _has_encoding_indicator({"resource": "encrypted_channel"}) is True
    assert _has_encoding_indicator({"tool": "read_file"}) is False


def test_compute_intervals():
    timestamps = [
        "2025-01-01T00:00:00Z",
        "2025-01-01T00:10:00Z",
        "2025-01-01T00:20:00Z",
    ]
    intervals = _compute_intervals(timestamps)
    assert len(intervals) == 2
    assert intervals[0] == 600.0
    assert intervals[1] == 600.0


def test_compute_intervals_empty():
    assert _compute_intervals([]) == []
    assert _compute_intervals(["2025-01-01T00:00:00Z"]) == []


def test_regularity_score_perfect():
    intervals = [600.0, 600.0, 600.0, 600.0]
    score = _regularity_score(intervals)
    assert score == 1.0


def test_regularity_score_zero():
    score = _regularity_score([])
    assert score == 0.0
    score = _regularity_score([100.0])
    assert score == 0.0


def test_regularity_score_medium():
    intervals = [600.0, 650.0, 580.0, 620.0]
    score = _regularity_score(intervals)
    assert 0.5 < score < 1.0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(4)
    ]
    r = analyze_c2(events)
    text = format_text(r)
    assert "Command-and-Control" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(4)
    ]
    r = analyze_c2(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "beacon_detections" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_c2([])
    text = format_text(r)
    assert "Command-and-Control" in text
    assert "0" in text


def test_summary_confidence_counts():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://c2.com/beacon",
         "timestamp": f"2025-01-01T00:{i*10:02d}:00Z"}
        for i in range(5)
    ]
    r = analyze_c2(events)
    total = sum(r.summary.by_confidence.values())
    assert total == r.summary.total_beacon_detections + r.summary.total_command_patterns


def test_too_few_calls_no_beacon():
    events = [
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.com",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "http_get", "resource": "https://api.com",
         "timestamp": "2025-01-01T00:10:00Z"},
    ]
    r = analyze_c2(events)
    assert r.summary.total_beacon_detections == 0
