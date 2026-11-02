"""Tests for agent behavioral drift analysis."""
from orbit_ir.agent_drift import (
    analyze_agent_drift,
    format_text,
    format_json,
    _detect_tool_drift,
    _detect_resource_drift,
    _detect_escalation_drift,
    _detect_communication_drift,
    _jensen_shannon,
)
from collections import Counter


def test_empty_events():
    r = analyze_agent_drift([], [])
    assert r.summary.total_signals == 0
    assert r.agents_analyzed == []


def test_no_drift():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_agent_drift(events)
    tool_drifts = [s for s in r.signals if s.drift_type == "tool-drift"]
    assert len(tool_drifts) == 0


def test_tool_drift_detected():
    early = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    late = [
        {"agent_id": "a1", "tool": "create_role", "resource": "roles/admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(early + late)
    tool_drifts = [s for s in r.signals if s.drift_type == "tool-drift"]
    assert len(tool_drifts) >= 1
    assert any("create_role" in s.description for s in tool_drifts)


def test_tool_drift_severity():
    early = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    late = [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(early + late)
    tool_drifts = [s for s in r.signals if s.drift_type == "tool-drift"]
    if tool_drifts:
        assert tool_drifts[0].severity in ("critical", "high", "medium")


def test_resource_drift_detected():
    early = [
        {"agent_id": "a1", "tool": "read", "resource": "file1.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    late = [
        {"agent_id": "a1", "tool": "read", "resource": f"secret{i}.key",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(early + late)
    res_drifts = [s for s in r.signals if s.drift_type == "resource-drift"]
    assert len(res_drifts) >= 1


def test_resource_drift_no_false_positive():
    events = [
        {"agent_id": "a1", "tool": "read", "resource": "file.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_agent_drift(events)
    res_drifts = [s for s in r.signals if s.drift_type == "resource-drift"]
    assert len(res_drifts) == 0


def test_escalation_drift_detected():
    early = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    late = [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin/role",
         "effect": "privilege-escalated", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(early + late)
    esc_drifts = [s for s in r.signals if s.drift_type == "escalation-drift"]
    assert len(esc_drifts) >= 1


def test_escalation_drift_no_false_positive():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(10)
    ]
    r = analyze_agent_drift(events)
    esc_drifts = [s for s in r.signals if s.drift_type == "escalation-drift"]
    assert len(esc_drifts) == 0


def test_communication_drift_detected():
    early = [
        {"agent_id": "a1", "tool": "send", "target_agent": "a2",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ]
    late = [
        {"agent_id": "a1", "tool": "send", "target_agent": f"a{i}",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(early + late)
    comm_drifts = [s for s in r.signals if s.drift_type == "communication-drift"]
    assert len(comm_drifts) >= 1


def test_multiple_agents():
    events = []
    for agent in ["a1", "a2"]:
        events.extend([
            {"agent_id": agent, "tool": "read_file", "resource": "data.txt",
             "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
            for i in range(5)
        ])
        events.extend([
            {"agent_id": agent, "tool": "create_admin", "resource": "admin",
             "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
            for i in range(5, 10)
        ])
    r = analyze_agent_drift(events)
    agents = {s.agent_id for s in r.signals}
    assert len(agents) == 2


def test_control_events_included():
    control = [
        {"agent_id": "a1", "actual_tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "actual_tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift([], control)
    assert r.summary.total_signals >= 1


def test_signal_ids_sequential():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(events)
    if r.signals:
        for i, s in enumerate(r.signals):
            assert s.signal_id == f"AD-{i + 1:03d}"


def test_severity_ordering():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "effect": "privilege-escalated",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(events)
    severities = [s.severity for s in r.signals]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(1, len(severities)):
        assert order.get(severities[i], 4) >= order.get(severities[i - 1], 4)


def test_jensen_shannon_identical():
    a = Counter({"x": 5, "y": 5})
    assert _jensen_shannon(a, a) < 0.01


def test_jensen_shannon_disjoint():
    a = Counter({"x": 10})
    b = Counter({"y": 10})
    assert _jensen_shannon(a, b) > 0.5


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(events)
    text = format_text(r)
    assert "Agent Behavioral Drift" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "signals" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_agent_drift([])
    text = format_text(r)
    assert "Agent Behavioral Drift" in text
    assert "0" in text


def test_summary_by_type():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5)
    ] + [
        {"agent_id": "a1", "tool": "create_admin", "resource": "admin",
         "timestamp": f"2025-01-01T00:{i:02d}:00Z"}
        for i in range(5, 10)
    ]
    r = analyze_agent_drift(events)
    assert sum(r.summary.by_type.values()) == r.summary.total_signals
