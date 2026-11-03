"""Tests for graph_export module."""

import json
import os
import tempfile

from orbit_ir.graph_export import build_graph, export_graphml, export_dot, format_report, load_events


def test_build_graph_basic():
    events = [
        {"agent": "agent_a", "target": "agent_b", "description": "lateral move"},
        {"agent": "agent_b", "resource": "/etc/passwd", "description": "file read"},
    ]
    g = build_graph(events)
    assert "agent_agent_a" in g["nodes"]
    assert "agent_agent_b" in g["nodes"]
    assert "resource_/etc/passwd" in g["nodes"]
    assert "event_0" in g["nodes"]
    assert "event_1" in g["nodes"]
    assert len(g["edges"]) > 0


def test_build_graph_empty():
    g = build_graph([])
    assert g["nodes"] == {}
    assert g["edges"] == []


def test_build_graph_string_events():
    events = ["something happened", "another thing"]
    g = build_graph(events)
    assert "event_0" in g["nodes"]
    assert "event_1" in g["nodes"]
    assert any(e["label"] == "next" for e in g["edges"])


def test_build_graph_none_events():
    events = [None, {"agent": "x", "description": "test"}, None]
    g = build_graph(events)
    assert "event_1" in g["nodes"]
    assert "event_0" not in g["nodes"]


def test_build_graph_chain():
    events = [{"description": "a"}, {"description": "b"}, {"description": "c"}]
    g = build_graph(events)
    next_edges = [e for e in g["edges"] if e["label"] == "next"]
    assert len(next_edges) == 2


def test_export_graphml():
    events = [{"agent": "a1", "target": "a2", "description": "test"}]
    g = build_graph(events)
    with tempfile.NamedTemporaryFile(suffix=".graphml", delete=False, mode="w") as f:
        path = f.name
    try:
        export_graphml(g, path)
        content = open(path).read()
        assert "graphml" in content
        assert "a1" in content
        assert "a2" in content
    finally:
        os.unlink(path)


def test_export_dot():
    events = [
        {"agent": "scanner", "resource": "db", "description": "scan"},
    ]
    g = build_graph(events)
    with tempfile.NamedTemporaryFile(suffix=".dot", delete=False, mode="w") as f:
        path = f.name
    try:
        export_dot(g, path)
        content = open(path).read()
        assert "digraph G" in content
        assert "scanner" in content
        assert "db" in content
    finally:
        os.unlink(path)


def test_format_report():
    events = [
        {"agent": "a1", "target": "a2", "description": "move"},
        {"agent": "a2", "resource": "secret.txt", "description": "read"},
    ]
    g = build_graph(events)
    text = format_report(g)
    assert "Graph Export Report" in text
    assert "Total nodes" in text
    assert "agent" in text
    assert "event" in text


def test_format_report_empty():
    g = build_graph([])
    text = format_report(g)
    assert "Total nodes:  0" in text
    assert "Total edges:  0" in text


def test_load_events_list():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump([{"a": 1}, {"b": 2}], f)
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 2
    finally:
        os.unlink(path)


def test_load_events_dict_with_events_key():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump({"events": [{"x": 1}]}, f)
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 1
    finally:
        os.unlink(path)


def test_load_events_single_dict():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump({"foo": "bar"}, f)
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 1
    finally:
        os.unlink(path)


def test_node_types():
    events = [{"agent": "bot", "resource": "/tmp/data", "description": "access"}]
    g = build_graph(events)
    assert g["nodes"]["agent_bot"]["type"] == "agent"
    assert g["nodes"]["resource_/tmp/data"]["type"] == "resource"
    assert g["nodes"]["event_0"]["type"] == "event"


def test_edge_labels():
    events = [{"agent": "a", "target": "b", "resource": "r", "description": "multi"}]
    g = build_graph(events)
    labels = {e["label"] for e in g["edges"]}
    assert "performed" in labels
    assert "targeted" in labels
    assert "accessed" in labels
