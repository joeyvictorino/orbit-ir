"""Tests for covert channel detection."""
import base64

from orbit_ir.covert_channel import (
    analyze_covert_channels,
    format_text,
    format_json,
    _is_metadata_tool,
    _is_timing_tool,
    _has_encoded_value,
    _is_unused_field,
    _regularity_score,
    _guess_timing_encoding,
)


def test_empty_events():
    r = analyze_covert_channels([])
    assert r.summary.total_timing_channels == 0
    assert r.summary.total_metadata_channels == 0
    assert r.summary.total_protocol_abuse == 0
    assert r.agents_involved == []


def test_normal_activity_no_detection():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "write_file", "resource": "output.txt",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.summary.total_timing_channels == 0
    assert r.summary.total_metadata_channels == 0


def test_timing_channel_binary():
    events = [
        {"agent_id": "a1", "tool": "sleep", "duration": 1.0,
         "timestamp": f"2025-01-01T00:00:{i*2:02d}Z"}
        for i in range(8)
    ]
    r = analyze_covert_channels(events)
    assert r.summary.total_timing_channels >= 1
    tc = r.timing_channels[0]
    assert tc.pattern_regularity >= 0.7
    assert tc.possible_encoding == "binary"


def test_timing_channel_varied_delays():
    events = []
    delays = [1, 0, 1, 1, 0, 1, 0, 0]
    for i, d in enumerate(delays):
        events.append({
            "agent_id": "a1",
            "tool": "delay",
            "duration": float(d) + 0.5,
            "timestamp": f"2025-01-01T00:00:{i*2:02d}Z",
        })
    r = analyze_covert_channels(events)
    assert r.summary.total_timing_channels >= 1


def test_metadata_channel_encoded():
    events = []
    for i in range(5):
        payload = base64.b64encode(f"secret-data-chunk-{i}".encode()).decode()
        events.append({
            "agent_id": "a1",
            "tool": "set_metadata",
            "field": "comment",
            "value": payload,
            "resource": "image.png",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    r = analyze_covert_channels(events)
    assert r.summary.total_metadata_channels >= 1
    mc = r.metadata_channels[0]
    assert mc.has_encoding is True
    assert mc.field_name == "comment"


def test_protocol_abuse_custom_header():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "https://api.example.com",
         "headers": {"x-custom": base64.b64encode(b"hidden-payload-data-that-is-quite-long-and-suspicious").decode()},
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.summary.total_protocol_abuse >= 1
    pa = r.protocol_abuse[0]
    assert pa.field_name == "x-custom"
    assert pa.has_encoding is True


def test_protocol_abuse_extra_field():
    payload = base64.b64encode(b"exfiltrated-data-payload-that-is-long-enough-to-trigger").decode()
    events = [
        {"agent_id": "a1", "tool": "api_call",
         "extra": payload,
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.summary.total_protocol_abuse >= 1


def test_is_metadata_tool():
    assert _is_metadata_tool("set_metadata") is True
    assert _is_metadata_tool("update_metadata") is True
    assert _is_metadata_tool("write_file") is False
    assert _is_metadata_tool("read_file") is False


def test_is_timing_tool():
    assert _is_timing_tool("sleep") is True
    assert _is_timing_tool("delay") is True
    assert _is_timing_tool("wait") is True
    assert _is_timing_tool("execute") is False


def test_has_encoded_value():
    assert _has_encoded_value("aGVsbG8gd29ybGQgdGVzdGluZw==") is True
    assert _has_encoded_value("hello world") is False
    assert _has_encoded_value("0123456789abcdef" * 2) is True


def test_is_unused_field():
    assert _is_unused_field("x-custom") is True
    assert _is_unused_field("x-data") is True
    assert _is_unused_field("Content-Type") is False
    assert _is_unused_field("reserved-field") is True


def test_regularity_score():
    assert _regularity_score([1.0, 1.0, 1.0, 1.0]) == 1.0
    assert _regularity_score([]) == 0.0
    assert _regularity_score([1.0]) == 0.0
    score = _regularity_score([1.0, 1.0, 10.0, 1.0])
    assert score < 0.7


def test_guess_timing_encoding():
    assert _guess_timing_encoding([1.0, 0.0, 1.0, 0.0]) == "binary"
    assert _guess_timing_encoding([3.0, 7.0, 1.0, 9.0]) == "decimal"
    assert _guess_timing_encoding([]) == "unknown"


def test_multi_agent():
    events = []
    for agent in ("a1", "a2"):
        for i in range(4):
            events.append({
                "agent_id": agent,
                "tool": "sleep",
                "duration": 1.0,
                "timestamp": f"2025-01-01T00:0{i}:00Z",
            })
    r = analyze_covert_channels(events)
    assert r.summary.agents_involved >= 2


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "sleep", "duration": 1.0,
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(8)
    ]
    r = analyze_covert_channels(events)
    text = format_text(r)
    assert "Covert Channel Detection Report" in text


def test_format_text_empty():
    r = analyze_covert_channels([])
    text = format_text(r)
    assert "Timing channels:     0" in text


def test_format_json_output():
    r = analyze_covert_channels([])
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "summary" in data
    assert data["summary"]["total_timing_channels"] == 0
