"""Tests for log anomaly detection."""
from orbit_ir.log_anomaly import (
    analyze_log_anomalies,
    format_text,
    format_json,
    _detect_frequency_spikes,
    _detect_novel_entries,
    _detect_time_gaps,
    _detect_repetitive_patterns,
)


def test_empty_events():
    r = analyze_log_anomalies([], [])
    assert r.summary.total_anomalies == 0
    assert r.agents_analyzed == []


def test_no_anomalies():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": f"file_{i}.txt",
         "timestamp": f"2025-01-01T{i:02d}:00:00Z"}
        for i in range(4)
    ]
    r = analyze_log_anomalies(events)
    reps = [a for a in r.anomalies if a.anomaly_type == "repetitive-pattern"]
    novels = [a for a in r.anomalies if a.anomaly_type == "novel-entry"]
    assert len(reps) == 0
    assert len(novels) == 0


def test_frequency_spike():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "file.txt",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(20)
    ] + [
        {"agent_id": "a1", "tool": "read", "resource": "file.txt",
         "timestamp": f"2025-01-01T01:00:{i:02d}Z"}
        for i in range(3)
    ]
    r = analyze_log_anomalies(events)
    spike = [a for a in r.anomalies if a.anomaly_type == "frequency-spike"]
    assert len(spike) >= 1


def test_frequency_spike_severity():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "f.txt",
         "timestamp": f"2025-01-01T00:00:0{i}Z"}
        for i in range(10)
    ] + [
        {"agent_id": "a1", "tool": "read", "resource": "f.txt",
         "timestamp": f"2025-01-01T02:0{i}:00Z"}
        for i in range(3)
    ]
    r = analyze_log_anomalies(events)
    spikes = [a for a in r.anomalies if a.anomaly_type == "frequency-spike"]
    if spikes:
        assert spikes[0].severity in ("critical", "high", "medium")


def test_novel_entries():
    baseline = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    novel = [
        {"agent_id": "a1", "tool": "create_admin", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 8)
    ]
    r = analyze_log_anomalies(baseline + novel)
    novels = [a for a in r.anomalies if a.anomaly_type == "novel-entry"]
    assert len(novels) >= 1
    assert any("create_admin" in a.description for a in novels)


def test_novel_entries_no_false_positive():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_log_anomalies(events)
    novels = [a for a in r.anomalies if a.anomaly_type == "novel-entry"]
    assert len(novels) == 0


def test_time_gap():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "r0", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r1", "timestamp": "2025-01-01T00:00:01Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r2", "timestamp": "2025-01-01T00:00:02Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r3", "timestamp": "2025-01-01T00:00:03Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r4", "timestamp": "2025-01-01T00:00:04Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r5", "timestamp": "2025-01-01T00:00:05Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r6", "timestamp": "2025-01-01T01:00:00Z"},
        {"agent_id": "a1", "tool": "read", "resource": "r7", "timestamp": "2025-01-01T01:00:01Z"},
    ]
    r = analyze_log_anomalies(events)
    gaps = [a for a in r.anomalies if a.anomaly_type == "time-gap"]
    assert len(gaps) >= 1


def test_time_gap_uniform_no_anomaly():
    events = [
        {"agent_id": "a1", "tool": "read", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_log_anomalies(events)
    gaps = [a for a in r.anomalies if a.anomaly_type == "time-gap"]
    assert len(gaps) == 0


def test_repetitive_pattern():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    reps = [a for a in r.anomalies if a.anomaly_type == "repetitive-pattern"]
    assert len(reps) >= 1
    assert any("5 times" in a.description for a in reps)


def test_repetitive_pattern_short_no_anomaly():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:0{i}Z"}
        for i in range(2)
    ] + [
        {"agent_id": "a1", "tool": "read", "resource": "other",
         "timestamp": "2025-01-01T00:00:03Z"},
    ]
    r = analyze_log_anomalies(events)
    reps = [a for a in r.anomalies if a.anomaly_type == "repetitive-pattern"]
    assert len(reps) == 0


def test_multiple_agents():
    events = []
    for agent in ["a1", "a2"]:
        events.extend([
            {"agent_id": agent, "tool": "scan", "resource": "target",
             "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
            for i in range(5)
        ])
    r = analyze_log_anomalies(events)
    agents = {a.agent_id for a in r.anomalies}
    assert len(agents) == 2


def test_control_events_included():
    control = [
        {"agent_id": "a1", "actual_tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies([], control)
    assert r.summary.total_anomalies >= 1


def test_anomaly_ids_sequential():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    if r.anomalies:
        for i, a in enumerate(r.anomalies):
            assert a.anomaly_id == f"LA-{i + 1:03d}"


def test_severity_ordering():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(10)
    ] + [
        {"agent_id": "a2", "tool": "read", "resource": "file.txt",
         "timestamp": f"2025-01-01T00:0{i}:00Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    severities = [a.severity for a in r.anomalies]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(1, len(severities)):
        assert order.get(severities[i], 4) >= order.get(severities[i - 1], 4)


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    text = format_text(r)
    assert "Log Anomaly" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "anomalies" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_log_anomalies([])
    text = format_text(r)
    assert "Log Anomaly" in text
    assert "0" in text


def test_summary_by_type():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    assert sum(r.summary.by_type.values()) == r.summary.total_anomalies


def test_summary_by_severity():
    events = [
        {"agent_id": "a1", "tool": "scan", "resource": "target",
         "timestamp": f"2025-01-01T00:00:{i:02d}Z"}
        for i in range(5)
    ]
    r = analyze_log_anomalies(events)
    assert sum(r.summary.by_severity.values()) == r.summary.total_anomalies
