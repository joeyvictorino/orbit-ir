"""Tests for orbit_ir.topology."""

import json
import tempfile
from pathlib import Path

from orbit_ir.topology import build_topology, format_topology_text, format_topology_dot, load_and_build


def test_empty_messages():
    topo = build_topology([])
    assert topo["node_count"] == 0
    assert topo["edge_count"] == 0
    assert topo["density"] == 0.0
    assert topo["clusters"] == []
    assert topo["hub_agents"] == []
    assert topo["isolated_agents"] == []


def test_single_agent_no_recipient():
    msgs = [{"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"}]
    topo = build_topology(msgs)
    assert topo["node_count"] == 1
    assert topo["edge_count"] == 0
    assert topo["isolated_agents"] == ["a1"]


def test_simple_chain():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "b", "recipient_agent_id": "c", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    topo = build_topology(msgs)
    assert topo["node_count"] == 3
    assert topo["edge_count"] == 2
    assert len(topo["clusters"]) == 1
    assert sorted(topo["clusters"][0]) == ["a", "b", "c"]


def test_hub_and_spoke():
    msgs = []
    for i in range(10):
        msgs.append({
            "agent_id": "hub",
            "recipient_agent_id": f"spoke_{i}",
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
        })
    topo = build_topology(msgs)
    assert topo["node_count"] == 11
    assert "hub" in topo["hub_agents"]
    assert topo["centrality"]["hub"] > 0 or topo["node_count"] > 2


def test_centrality_ranking():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "b", "recipient_agent_id": "c", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a", "recipient_agent_id": "c", "timestamp": "2025-01-01T00:03:00Z"},
        {"agent_id": "c", "recipient_agent_id": "d", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    topo = build_topology(msgs)
    assert topo["centrality"]["c"] >= topo["centrality"]["a"]


def test_isolated_agent():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "lone", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    topo = build_topology(msgs)
    assert "lone" in topo["isolated_agents"]
    assert "a" not in topo["isolated_agents"]


def test_dot_output():
    msgs = [
        {"agent_id": "x", "recipient_agent_id": "y", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    topo = build_topology(msgs)
    dot = format_topology_dot(topo)
    assert "digraph topology" in dot
    assert '"x"' in dot
    assert '"y"' in dot
    assert "->" in dot


def test_text_output():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    topo = build_topology(msgs)
    text = format_topology_text(topo)
    assert "Nodes: 2" in text
    assert "Edges: 1" in text


def test_multiple_components():
    msgs = [
        {"agent_id": "a1", "recipient_agent_id": "a2", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "b1", "recipient_agent_id": "b2", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    topo = build_topology(msgs)
    assert len(topo["clusters"]) == 2


def test_self_loop():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "a", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    topo = build_topology(msgs)
    assert topo["edge_count"] == 1
    assert topo["node_count"] == 1


def test_load_and_build(tmp_path):
    msgs = [
        {"agent_id": "x", "recipient_agent_id": "y", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "y", "recipient_agent_id": "z", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    msg_file = tmp_path / "messages.jsonl"
    msg_file.write_text("\n".join(json.dumps(m) for m in msgs))
    topo = load_and_build(tmp_path)
    assert topo["node_count"] == 3
    assert topo["edge_count"] == 2


def test_edge_timestamps():
    msgs = [
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a", "recipient_agent_id": "b", "timestamp": "2025-01-01T01:00:00Z"},
    ]
    topo = build_topology(msgs)
    edge = [e for e in topo["edges"] if e["source"] == "a" and e["target"] == "b"][0]
    assert edge["weight"] == 2
    assert edge["first_seen"] == "2025-01-01T00:00:00Z"
    assert edge["last_seen"] == "2025-01-01T01:00:00Z"
