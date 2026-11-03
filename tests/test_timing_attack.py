"""Tests for timing-based attack pattern detection."""
import json
from datetime import datetime, timezone

from orbit_ir.timing_attack import (
    analyze,
    format_text,
    format_json,
    _load_events,
    _parse_ts,
    BURST_THRESHOLD,
)


def _ts(minute, second=0, hour=12):
    return f"2025-01-01T{hour:02d}:{minute:02d}:{second:02d}Z"


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_anomalies == 0
    assert r.agents_involved == []


def test_no_anomalies():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": _ts(0), "tool_call_id": "tc1"},
        {"agent_id": "a1", "tool": "read_file", "resource": "data2.txt",
         "timestamp": _ts(5), "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    assert r.summary.total_anomalies == 0


def test_burst_detection():
    events = []
    for i in range(7):
        events.append({
            "agent_id": "a1", "tool": "write", "resource": f"file{i}.txt",
            "timestamp": f"2025-01-01T12:00:{i:02d}Z", "tool_call_id": f"tc{i}",
        })
    r = analyze(events, [])
    burst_anomalies = [a for a in r.anomalies if a.anomaly_type == "burst"]
    assert len(burst_anomalies) >= 1
    assert burst_anomalies[0].severity in ("medium", "high")


def test_burst_high_severity():
    events = []
    for i in range(BURST_THRESHOLD * 2):
        events.append({
            "agent_id": "a1", "tool": "write", "resource": f"file{i}.txt",
            "timestamp": f"2025-01-01T12:00:{i % 10:02d}Z", "tool_call_id": f"tc{i}",
        })
    r = analyze(events, [])
    burst_anomalies = [a for a in r.anomalies if a.anomaly_type == "burst"]
    assert len(burst_anomalies) >= 1
    assert burst_anomalies[0].severity == "high"


def test_toctou_detection():
    events = [
        {"agent_id": "a1", "claimed_tool": "check_access", "resource": "secret/file.key",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "claimed_tool": "write_file", "resource": "secret/file.key",
         "timestamp": "2025-01-01T12:00:15Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    toctou = [a for a in r.anomalies if a.anomaly_type == "toctou"]
    assert len(toctou) >= 1
    assert toctou[0].severity == "high"
    assert "secret/file.key" in toctou[0].resources


def test_toctou_different_resources_no_match():
    events = [
        {"agent_id": "a1", "claimed_tool": "check_access", "resource": "file_a",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "claimed_tool": "write_file", "resource": "file_b",
         "timestamp": "2025-01-01T12:00:05Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    toctou = [a for a in r.anomalies if a.anomaly_type == "toctou"]
    assert len(toctou) == 0


def test_coordinated_timing():
    events = [
        {"agent_id": "a1", "tool": "modify_policy", "resource": "policy/main",
         "timestamp": "2025-01-01T12:00:00.000Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "tool": "create_role", "resource": "roles/admin",
         "timestamp": "2025-01-01T12:00:01.000Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    coord = [a for a in r.anomalies if a.anomaly_type == "coordinated"]
    assert len(coord) >= 1
    assert "a2" in coord[0].related_agents or "a1" in coord[0].related_agents


def test_dormant_burst():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "x",
         "timestamp": "2025-01-01T10:00:00Z", "tool_call_id": "tc0"},
        {"agent_id": "a1", "tool": "write", "resource": "y",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "tool": "write", "resource": "z",
         "timestamp": "2025-01-01T12:00:10Z", "tool_call_id": "tc2"},
        {"agent_id": "a1", "tool": "write", "resource": "w",
         "timestamp": "2025-01-01T12:00:20Z", "tool_call_id": "tc3"},
    ]
    r = analyze(events, [])
    dormant = [a for a in r.anomalies if a.anomaly_type == "dormant-burst"]
    assert len(dormant) >= 1
    assert dormant[0].duration_seconds >= 3600


def test_off_hours_activity():
    events = [
        {"agent_id": "a1", "tool": "modify", "resource": "secret/keys",
         "timestamp": "2025-01-01T02:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "tool": "write", "resource": "config/admin",
         "timestamp": "2025-01-01T03:30:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    off = [a for a in r.anomalies if a.anomaly_type == "off-hours"]
    assert len(off) >= 1


def test_off_hours_single_event_no_flag():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "data",
         "timestamp": "2025-01-01T03:00:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    off = [a for a in r.anomalies if a.anomaly_type == "off-hours"]
    assert len(off) == 0


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "check", "resource": "file.txt",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "tool": "write", "resource": "file.txt",
         "timestamp": "2025-01-01T12:00:10Z", "tool_call_id": "tc2"},
        {"agent_id": "a2", "tool": "verify", "resource": "config.yaml",
         "timestamp": "2025-01-01T12:01:00Z", "tool_call_id": "tc3"},
        {"agent_id": "a2", "tool": "modify", "resource": "config.yaml",
         "timestamp": "2025-01-01T12:01:15Z", "tool_call_id": "tc4"},
    ]
    r = analyze(events, [])
    assert r.summary.agents_involved >= 2


def test_control_events_used():
    control = [
        {"agent_id": "a1", "actual_tool": "check_perm", "resource": "secret/x",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "actual_tool": "write_secret", "resource": "secret/x",
         "timestamp": "2025-01-01T12:00:10Z", "tool_call_id": "tc2"},
    ]
    r = analyze([], control)
    toctou = [a for a in r.anomalies if a.anomaly_type == "toctou"]
    assert len(toctou) >= 1


def test_severity_ordering():
    events = [
        {"agent_id": "a1", "claimed_tool": "check", "resource": "secret/file",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "claimed_tool": "write", "resource": "secret/file",
         "timestamp": "2025-01-01T12:00:10Z", "tool_call_id": "tc2"},
        {"agent_id": "a2", "tool": "modify", "resource": "data",
         "timestamp": "2025-01-01T02:00:00Z", "tool_call_id": "tc3"},
        {"agent_id": "a2", "tool": "read", "resource": "data2",
         "timestamp": "2025-01-01T03:00:00Z", "tool_call_id": "tc4"},
    ]
    r = analyze(events, [])
    if len(r.anomalies) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(r.anomalies) - 1):
            assert sev_order.get(r.anomalies[i].severity, 4) <= sev_order.get(r.anomalies[i + 1].severity, 4)


def test_format_text_output():
    events = []
    for i in range(6):
        events.append({
            "agent_id": "a1", "tool": "write", "resource": f"f{i}",
            "timestamp": f"2025-01-01T12:00:{i:02d}Z", "tool_call_id": f"tc{i}",
        })
    r = analyze(events, [])
    text = format_text(r)
    assert "Timing Attack" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "claimed_tool": "check", "resource": "file.txt",
         "timestamp": "2025-01-01T12:00:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a1", "claimed_tool": "write", "resource": "file.txt",
         "timestamp": "2025-01-01T12:00:10Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    out = format_json(r)
    data = json.loads(out)
    assert "anomalies" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Timing Attack" in text
    assert "0" in text


def test_parse_ts_formats():
    assert _parse_ts("2025-01-01T12:00:00Z") is not None
    assert _parse_ts("2025-01-01T12:00:00.123Z") is not None
    assert _parse_ts("") is None
    assert _parse_ts("not-a-date") is None


def test_load_events(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"agent_id": "a1", "timestamp": "2025-01-01T12:00:00Z"}\n')
    events = _load_events(p)
    assert len(events) == 1


def test_load_events_missing():
    events = _load_events("/nonexistent/path.jsonl")
    assert events == []


def test_summary_by_type():
    events = []
    for i in range(6):
        events.append({
            "agent_id": "a1", "tool": "write", "resource": f"f{i}",
            "timestamp": f"2025-01-01T12:00:{i:02d}Z", "tool_call_id": f"tc{i}",
        })
    events.append({"agent_id": "a1", "claimed_tool": "check", "resource": "x",
                    "timestamp": "2025-01-01T12:05:00Z", "tool_call_id": "tc10"})
    events.append({"agent_id": "a1", "claimed_tool": "write", "resource": "x",
                    "timestamp": "2025-01-01T12:05:15Z", "tool_call_id": "tc11"})
    r = analyze(events, [])
    assert sum(r.summary.by_type.values()) == r.summary.total_anomalies
