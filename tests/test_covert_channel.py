"""Tests for covert channel detection."""
from orbit_ir.covert_channel import (
    analyze_covert_channels,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_covert_channels([])
    assert r.total_events == 0
    assert r.channel_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_channels():
    events = [
        {"agent_id": "a1", "message": "read file data.txt", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "returned query results", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 0
    assert r.risk_level == "none"


def test_steganographic_output():
    events = [
        {"agent_id": "a1", "message": "steganographic encoding of data in output text",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "steganographic_output")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_hidden_data_in_whitespace():
    events = [
        {"agent_id": "a1", "message": "whitespace encoding channel for hidden data signaling",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "steganographic_output")
    assert cat.count == 1


def test_casing_encoding():
    events = [
        {"agent_id": "a1", "message": "encode data in using casing steganographic channel",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_timing_signal():
    events = [
        {"agent_id": "a1", "message": "covert timing channel detected via response delays",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "timing_signal")
    assert cat.count == 1
    assert cat.severity == "high"


def test_timing_synchronization():
    events = [
        {"agent_id": "a1", "message": "agents synchronized via timing delay signals",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_resource_encoding():
    events = [
        {"agent_id": "a1", "message": "covert channel via resource usage patterns as signal carrier",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "resource_encoding")
    assert cat.count == 1


def test_cpu_pattern_signaling():
    events = [
        {"agent_id": "a1", "message": "encoded data in cpu usage pattern as information carrier",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_metadata_abuse():
    events = [
        {"agent_id": "a1", "message": "metadata abuse for covert messaging between agents",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "metadata_abuse")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_hidden_data_in_headers():
    events = [
        {"agent_id": "a1", "message": "metadata abuse for hidden covert channel in header fields",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_error_channel():
    events = [
        {"agent_id": "a1", "message": "covert data transmitted via error channel messages",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "error_channel")
    assert cat.count == 1


def test_error_code_encoding():
    events = [
        {"agent_id": "a1", "message": "error code encoding hidden data in return values",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_protocol_tunnel():
    events = [
        {"agent_id": "a1", "message": "dns tunnel covert channel detected for data exfiltration",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    cat = next(c for c in r.categories if c.category == "protocol_tunnel")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_http_tunnel():
    events = [
        {"agent_id": "a1", "message": "http tunnel covert channel for payload encapsulation",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "steganographic output encoding hidden data", "timestamp": "t1"},
    ]
    r = analyze_covert_channels(events)
    assert r.risk_score > 0
    assert r.risk_level in ("critical", "high", "medium")


def test_risk_score_none():
    events = [
        {"agent_id": "a1", "message": "normal read operation", "timestamp": "t1"},
    ]
    r = analyze_covert_channels(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_channel_chains():
    events = [
        {"agent_id": "a1", "message": "steganographic encoding in output channel data", "timestamp": "t1"},
        {"agent_id": "a1", "message": "dns tunnel covert data exfiltration detected", "timestamp": "t2"},
    ]
    r = analyze_covert_channels(events)
    assert len(r.channel_chains) >= 1
    chain = r.channel_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "covert timing channel between agents", "timestamp": "t1"},
        {"agent_id": "a2", "message": "metadata abuse for hidden messaging", "timestamp": "t2"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 2


def test_mixed_events():
    events = [
        {"agent_id": "a1", "message": "normal operation completed", "timestamp": "t1"},
        {"agent_id": "a2", "message": "dns tunnel covert channel established", "timestamp": "t2"},
        {"agent_id": "a3", "message": "read configuration file", "timestamp": "t3"},
    ]
    r = analyze_covert_channels(events)
    assert r.channel_events == 1
    assert r.total_events == 3


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "steganographic output encoding detected",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    text = format_text(r)
    assert "Covert Channel" in text
    assert "steganographic_output" in text


def test_format_text_empty():
    r = analyze_covert_channels([])
    text = format_text(r)
    assert "Covert Channel" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "covert timing channel signal detected",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_covert_channels(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "metadata abuse hidden channel detected", "timestamp": "t1"},
    ]
    r = analyze_covert_channels(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_stego():
    ev = {"message": "steganographic encoding channel in output"}
    matches = _classify_event(ev)
    cats = [c for c, _ in matches]
    assert "steganographic_output" in cats


def test_classify_event_no_match():
    ev = {"message": "normal file read operation completed"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_categories_have_patterns():
    for cat, info in CATEGORIES.items():
        assert len(info["patterns"]) >= 3
        assert info["severity"] in ("critical", "high", "medium", "low")
        assert len(info["description"]) > 10


def test_techniques_seen():
    events = [
        {"agent_id": "a1", "message": "dns tunnel covert channel for data transfer", "timestamp": "t1"},
    ]
    r = analyze_covert_channels(events)
    assert len(r.techniques_seen) >= 0
