"""Tests for action_sequence module."""
import json

from orbit_ir.action_sequence import (
    ActionSequenceReport,
    analyze_action_sequences,
    format_json,
    format_text,
)


def test_empty_events():
    r = analyze_action_sequences([])
    assert r.summary.total_actions == 0
    assert r.summary.agents_analyzed == 0


def test_single_action():
    events = [
        {"agent_id": "a1", "tool": "read_file"},
    ]
    r = analyze_action_sequences(events)
    assert r.summary.total_actions == 1
    assert r.summary.unique_actions == 1
    assert r.summary.total_patterns == 0


def test_repeated_pattern():
    events = []
    for _ in range(3):
        events.append({"agent_id": "a1", "tool": "read_file"})
        events.append({"agent_id": "a1", "tool": "write_file"})
    r = analyze_action_sequences(events, min_frequency=2)
    found = False
    for p in r.patterns:
        if p.sequence == ["read_file", "write_file"] and p.frequency >= 2:
            found = True
    assert found, "expected repeated read_file->write_file pattern"


def test_transition_probabilities():
    events = [
        {"agent_id": "a1", "tool": "scan"},
        {"agent_id": "a1", "tool": "analyze"},
        {"agent_id": "a1", "tool": "scan"},
        {"agent_id": "a1", "tool": "analyze"},
        {"agent_id": "a1", "tool": "scan"},
        {"agent_id": "a1", "tool": "report"},
    ]
    r = analyze_action_sequences(events)
    scan_transitions = [t for t in r.transitions if t.from_action == "scan"]
    assert len(scan_transitions) >= 1
    probs = {t.to_action: t.probability for t in scan_transitions}
    assert "analyze" in probs


def test_anomalous_sequence():
    events = []
    for _ in range(5):
        events.append({"agent_id": "a1", "tool": "read_file"})
        events.append({"agent_id": "a1", "tool": "write_file"})
    events.append({"agent_id": "a1", "tool": "delete_all"})
    events.append({"agent_id": "a1", "tool": "exfiltrate"})
    r = analyze_action_sequences(events, min_frequency=1)
    assert r.summary.anomalous_patterns > 0


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "scan"},
        {"agent_id": "a1", "tool": "report"},
        {"agent_id": "a2", "tool": "scan"},
        {"agent_id": "a2", "tool": "report"},
    ]
    r = analyze_action_sequences(events, min_frequency=2)
    assert r.summary.agents_analyzed == 2
    found = False
    for p in r.patterns:
        if p.sequence == ["scan", "report"] and len(p.agents) == 2:
            found = True
    assert found


def test_format_text_contains_header():
    r = analyze_action_sequences([])
    out = format_text(r)
    assert "Action Sequence Pattern Analysis" in out


def test_format_json_valid():
    events = [
        {"agent_id": "a1", "tool": "scan"},
        {"agent_id": "a1", "tool": "report"},
    ]
    r = analyze_action_sequences(events)
    out = format_json(r)
    parsed = json.loads(out)
    assert "patterns" in parsed
    assert "transitions" in parsed
    assert "summary" in parsed


def test_max_sequence_length():
    events = [{"agent_id": "a1", "tool": f"t{i}"} for i in range(10)]
    r = analyze_action_sequences(events, min_frequency=1, max_sequence_length=3)
    for p in r.patterns:
        assert len(p.sequence) <= 3
