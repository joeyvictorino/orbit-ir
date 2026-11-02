"""Tests for steganographic channel detection."""
import json

from orbit_ir.steganography import (
    analyze_steganography,
    format_text,
    format_json,
    _shannon_entropy,
    _has_encoding_patterns,
    _has_suspicious_metadata,
    _output_entropy_anomaly,
)


def test_empty_events():
    r = analyze_steganography([])
    assert r.summary.total_detections == 0
    assert r.agents_involved == []
    assert r.timeline == []


def test_no_stego_in_normal_events():
    events = [
        {"agent_id": "a1", "output": "Hello, world!", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1"},
        {"agent_id": "a1", "output": "Task complete.", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    assert r.summary.total_detections == 0


def test_encoding_channel_detection():
    events = [
        {"agent_id": "a1", "output": "Result: base64 encoded \\x41\\x42 data here base64 more hex: stuff",
         "timestamp": "2025-01-01T00:00:00Z", "event_id": "ev1"},
        {"agent_id": "a1", "output": "More base64 payload with \\x00\\x01 bytes embedded base64",
         "timestamp": "2025-01-01T00:01:00Z", "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    assert r.summary.total_detections >= 1
    enc_dets = [d for d in r.detections if d.technique == "encoding-channel"]
    assert len(enc_dets) >= 1
    assert enc_dets[0].agent_id == "a1"


def test_metadata_signaling_detection():
    events = [
        {"agent_id": "a1", "output": "Normal output", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc123"}},
        {"agent_id": "a1", "output": "Another output", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev2", "metadata": {"x-data": "payload", "x-custom": "marker"}},
    ]
    r = analyze_steganography(events)
    meta_dets = [d for d in r.detections if d.technique == "metadata-signaling"]
    assert len(meta_dets) >= 1
    assert meta_dets[0].agent_id == "a1"


def test_output_embedding_high_entropy():
    import random
    random.seed(42)
    high_entropy = "".join(chr(random.randint(33, 126)) for _ in range(200))
    events = [
        {"agent_id": "a1", "output": high_entropy, "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1"},
        {"agent_id": "a1", "output": high_entropy[::-1], "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    emb_dets = [d for d in r.detections if d.technique == "output-embedding"]
    assert len(emb_dets) >= 1


def test_structural_anomaly_detection():
    short = "Normal short output here."
    long_output = "x" * 5000
    events = [
        {"agent_id": "a1", "output": short, "timestamp": f"2025-01-01T00:0{i}:00Z", "event_id": f"ev{i}"}
        for i in range(10)
    ]
    events.append({"agent_id": "a1", "output": long_output, "timestamp": "2025-01-01T00:20:00Z", "event_id": "ev20"})
    r = analyze_steganography(events)
    struct_dets = [d for d in r.detections if d.technique == "structural-anomaly"]
    assert len(struct_dets) >= 1


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "yes"}},
        {"agent_id": "a2", "output": "Normal", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev2", "metadata": {"x-data": "payload"}},
    ]
    r = analyze_steganography(events)
    assert r.summary.agents_involved >= 1


def test_confidence_levels():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": f"2025-01-01T00:0{i}:00Z",
         "event_id": f"ev{i}", "metadata": {"x-signal": f"val{i}"}}
        for i in range(5)
    ]
    r = analyze_steganography(events)
    meta_dets = [d for d in r.detections if d.technique == "metadata-signaling"]
    if meta_dets:
        assert meta_dets[0].confidence == "high"


def test_channel_capacity_estimate():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc"}},
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev2", "metadata": {"x-data": "xyz"}},
    ]
    r = analyze_steganography(events)
    for d in r.detections:
        assert d.channel_capacity_estimate >= 0


def test_timeline_ordering():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:02:00Z",
         "event_id": "ev2", "metadata": {"x-signal": "abc"}},
        {"agent_id": "a2", "output": "Normal", "timestamp": "2025-01-01T00:01:00Z",
         "event_id": "ev1", "metadata": {"x-data": "xyz"}},
    ]
    r = analyze_steganography(events)
    if len(r.timeline) >= 2:
        assert r.timeline[0]["timestamp"] <= r.timeline[1]["timestamp"]


def test_shannon_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_uniform():
    ent = _shannon_entropy("abcd")
    assert ent == 2.0


def test_shannon_entropy_single_char():
    assert _shannon_entropy("aaaa") == 0.0


def test_has_encoding_patterns_base64():
    matches = _has_encoding_patterns("data:image/png;base64,abc123")
    assert len(matches) >= 1


def test_has_encoding_patterns_hex():
    matches = _has_encoding_patterns("\\x41\\x42\\x43")
    assert len(matches) >= 1


def test_has_encoding_patterns_none():
    matches = _has_encoding_patterns("Hello, world!")
    assert len(matches) == 0


def test_has_suspicious_metadata_x_prefix():
    ev = {"metadata": {"x-custom": "value"}}
    keys = _has_suspicious_metadata(ev)
    assert "x-custom" in keys


def test_has_suspicious_metadata_top_level():
    ev = {"hidden": "data", "output": "normal"}
    keys = _has_suspicious_metadata(ev)
    assert "hidden" in keys


def test_has_suspicious_metadata_clean():
    ev = {"agent_id": "a1", "output": "data"}
    keys = _has_suspicious_metadata(ev)
    assert len(keys) == 0


def test_output_entropy_anomaly_short():
    assert _output_entropy_anomaly("short") is False


def test_output_entropy_anomaly_low():
    assert _output_entropy_anomaly("a" * 100) is False


def test_detection_id_format():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc"}},
    ]
    r = analyze_steganography(events)
    for d in r.detections:
        assert d.detection_id.startswith("STEGO-")


def test_format_text_output():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc", "x-data": "xyz"}},
    ]
    r = analyze_steganography(events)
    text = format_text(r)
    assert "Steganographic Channel Detection" in text
    assert "a1" in text


def test_format_text_empty():
    r = analyze_steganography([])
    text = format_text(r)
    assert "Steganographic Channel Detection" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc"}},
    ]
    r = analyze_steganography(events)
    out = format_json(r)
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data
    assert "agents_involved" in data
    assert "timeline" in data


def test_format_json_empty():
    r = analyze_steganography([])
    out = format_json(r)
    data = json.loads(out)
    assert data["summary"]["total_detections"] == 0


def test_summary_by_technique():
    events = [
        {"agent_id": "a1", "output": "base64 encoded \\x41\\x42 data base64 payload",
         "timestamp": "2025-01-01T00:00:00Z", "event_id": "ev1"},
        {"agent_id": "a1", "output": "base64 again \\x00\\x01 bytes base64 more",
         "timestamp": "2025-01-01T00:01:00Z", "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    total_by_tech = sum(r.summary.by_technique.values())
    assert total_by_tech == r.summary.total_detections


def test_summary_by_confidence():
    events = [
        {"agent_id": "a1", "output": "Normal", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1", "metadata": {"x-signal": "abc"}},
    ]
    r = analyze_steganography(events)
    total_by_conf = sum(r.summary.by_confidence.values())
    assert total_by_conf == r.summary.total_detections


def test_highest_entropy_agent():
    import random
    random.seed(99)
    high_ent = "".join(chr(random.randint(33, 126)) for _ in range(200))
    events = [
        {"agent_id": "a1", "output": "aaaa" * 20, "timestamp": "2025-01-01T00:00:00Z", "event_id": "ev1"},
        {"agent_id": "a2", "output": high_ent, "timestamp": "2025-01-01T00:01:00Z", "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    assert r.summary.highest_entropy_agent == "a2"


def test_response_field_fallback():
    events = [
        {"agent_id": "a1", "response": "base64 encoded \\x41\\x42 data base64 payload",
         "timestamp": "2025-01-01T00:00:00Z", "event_id": "ev1"},
        {"agent_id": "a1", "response": "base64 again \\x00\\x01 bytes base64 more",
         "timestamp": "2025-01-01T00:01:00Z", "event_id": "ev2"},
    ]
    r = analyze_steganography(events)
    enc_dets = [d for d in r.detections if d.technique == "encoding-channel"]
    assert len(enc_dets) >= 1


def test_no_agent_id_skipped():
    events = [
        {"output": "base64 \\x41\\x42 stuff base64", "timestamp": "2025-01-01T00:00:00Z",
         "event_id": "ev1"},
    ]
    r = analyze_steganography(events)
    assert r.summary.total_detections == 0
