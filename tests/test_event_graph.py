"""Tests for event_graph module."""
import json

from orbit_ir.event_graph import (
    analyze_event_graph,
    format_text,
    format_json,
    _build_nodes,
    _build_temporal_edges,
    _find_components,
    GraphNode,
)


def test_empty_events():
    r = analyze_event_graph([])
    assert r.summary.total_nodes == 0
    assert r.summary.total_edges == 0


def test_single_agent_sequence():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z", "tool": "read"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z", "tool": "write"},
    ]
    r = analyze_event_graph(events)
    assert r.summary.total_nodes == 2
    assert r.summary.total_edges >= 1
    temporal = [e for e in r.edges if e.edge_type == "temporal-sequence"]
    assert len(temporal) == 1
    assert temporal[0].source == "e1"
    assert temporal[0].target == "e2"


def test_multi_agent_no_cross_temporal():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z"},
    ]
    r = analyze_event_graph(events)
    temporal = [e for e in r.edges if e.edge_type == "temporal-sequence"]
    assert len(temporal) == 0


def test_resource_dependency_edges():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "action": "write", "resource": "/data/file.txt"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "action": "read", "resource": "/data/file.txt"},
    ]
    r = analyze_event_graph(events)
    resource_edges = [e for e in r.edges if e.edge_type == "resource-dependency"]
    assert len(resource_edges) >= 1


def test_causal_edges():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "parent_event_id": "e1"},
    ]
    r = analyze_event_graph(events)
    causal = [e for e in r.edges if e.edge_type == "causal"]
    assert len(causal) == 1
    assert causal[0].source == "e1"
    assert causal[0].target == "e2"


def test_connected_components():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "t2"},
        {"agent_id": "a2", "event_id": "e3", "timestamp": "t3"},
    ]
    r = analyze_event_graph(events)
    assert r.summary.connected_components >= 1


def test_critical_path():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z"},
        {"agent_id": "a1", "event_id": "e3", "timestamp": "2026-01-01T00:02:00Z"},
    ]
    r = analyze_event_graph(events)
    assert len(r.critical_paths) >= 1
    assert r.critical_paths[0].total_weight > 0


def test_no_agent_id_skipped():
    events = [
        {"event_id": "e1", "timestamp": "t1", "tool": "read"},
    ]
    r = analyze_event_graph(events)
    assert r.summary.total_nodes == 0


def test_no_event_id_skipped():
    events = [
        {"agent_id": "a1", "timestamp": "t1", "tool": "read"},
    ]
    r = analyze_event_graph(events)
    assert r.summary.total_nodes == 0


def test_build_nodes_sorting():
    events = [
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:02:00Z"},
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:01:00Z"},
    ]
    nodes = _build_nodes(events)
    assert nodes[0].event_id == "e1"
    assert nodes[1].event_id == "e2"


def test_edge_deduplication():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "action": "write", "resource": "/f"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "action": "read", "resource": "/f"},
    ]
    r = analyze_event_graph(events)
    keys = [(e.source, e.target, e.edge_type) for e in r.edges]
    assert len(keys) == len(set(keys))


def test_most_connected_node():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z"},
        {"agent_id": "a1", "event_id": "e3", "timestamp": "2026-01-01T00:02:00Z"},
    ]
    r = analyze_event_graph(events)
    assert r.summary.most_connected_node != ""


def test_agents_involved():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "t2"},
        {"agent_id": "a3", "event_id": "e3", "timestamp": "t3"},
    ]
    r = analyze_event_graph(events)
    assert r.agents_involved == ["a1", "a2", "a3"]


def test_edge_types_counted():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z"},
    ]
    r = analyze_event_graph(events)
    assert "temporal-sequence" in r.summary.edge_types


def test_format_text_output():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "t2"},
    ]
    r = analyze_event_graph(events)
    text = format_text(r)
    assert "Event Dependency Graph Report" in text


def test_format_text_empty():
    text = format_text(analyze_event_graph([]))
    assert "Event Dependency Graph Report" in text
    assert "0" in text


def test_format_json_valid():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1"},
    ]
    data = json.loads(format_json(analyze_event_graph(events)))
    assert "nodes" in data
    assert "edges" in data
    assert "clusters" in data
    assert "summary" in data


def test_format_json_empty():
    data = json.loads(format_json(analyze_event_graph([])))
    assert data["summary"]["total_nodes"] == 0


def test_triggered_by_causal():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "t2", "triggered_by": "e1"},
    ]
    r = analyze_event_graph(events)
    causal = [e for e in r.edges if e.edge_type == "causal"]
    assert len(causal) == 1


def test_large_graph():
    events = []
    for i in range(50):
        events.append({
            "agent_id": f"a{i % 5}",
            "event_id": f"e{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "tool": "read",
        })
    r = analyze_event_graph(events)
    assert r.summary.total_nodes == 50
    assert r.summary.total_agents == 5
