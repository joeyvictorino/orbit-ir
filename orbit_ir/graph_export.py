"""Graph export module for agent incident reconstruction."""

import json
import xml.etree.ElementTree as ET


def build_graph(events):
    nodes = {}
    edges = []

    for i, event in enumerate(events):
        if event is None:
            continue
        if isinstance(event, str):
            event = {"description": event}
        if not isinstance(event, dict):
            continue

        event_id = f"event_{i}"
        nodes[event_id] = {"type": "event", "label": str(event.get("description", event.get("type", f"event {i}")))[:80]}

        agent = event.get("agent") or event.get("source_agent") or event.get("actor")
        if agent:
            agent_id = f"agent_{agent}"
            if agent_id not in nodes:
                nodes[agent_id] = {"type": "agent", "label": str(agent)}
            edges.append({"source": agent_id, "target": event_id, "label": "performed"})

        target = event.get("target") or event.get("target_agent") or event.get("destination")
        if target:
            target_id = f"agent_{target}"
            if target_id not in nodes:
                nodes[target_id] = {"type": "agent", "label": str(target)}
            edges.append({"source": event_id, "target": target_id, "label": "targeted"})

        resource = event.get("resource") or event.get("file") or event.get("path")
        if resource:
            res_id = f"resource_{resource}"
            if res_id not in nodes:
                nodes[res_id] = {"type": "resource", "label": str(resource)}
            edges.append({"source": event_id, "target": res_id, "label": "accessed"})

    # Chain sequential events
    event_ids = [k for k in sorted(nodes) if k.startswith("event_")]
    for j in range(len(event_ids) - 1):
        edges.append({"source": event_ids[j], "target": event_ids[j + 1], "label": "next"})

    return {"nodes": nodes, "edges": edges}


def export_graphml(graph, path):
    ns = "http://graphml.graphstruct.org/xmlns"
    root = ET.Element("graphml", xmlns=ns)

    ET.SubElement(root, "key", id="d0", attrib={"for": "node", "attr.name": "label", "attr.type": "string"})
    ET.SubElement(root, "key", id="d1", attrib={"for": "node", "attr.name": "type", "attr.type": "string"})
    ET.SubElement(root, "key", id="d2", attrib={"for": "edge", "attr.name": "label", "attr.type": "string"})

    g = ET.SubElement(root, "graph", id="G", edgedefault="directed")

    for node_id, attrs in graph["nodes"].items():
        n = ET.SubElement(g, "node", id=node_id)
        d0 = ET.SubElement(n, "data", key="d0")
        d0.text = attrs.get("label", node_id)
        d1 = ET.SubElement(n, "data", key="d1")
        d1.text = attrs.get("type", "unknown")

    for i, edge in enumerate(graph["edges"]):
        e = ET.SubElement(g, "edge", id=f"e{i}", source=edge["source"], target=edge["target"])
        d2 = ET.SubElement(e, "data", key="d2")
        d2.text = edge.get("label", "")

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, xml_declaration=True, encoding="unicode")


def export_dot(graph, path):
    lines = ["digraph G {", '  rankdir=LR;', '  node [shape=box];']

    shape_map = {"agent": "ellipse", "resource": "cylinder", "event": "box"}
    for node_id, attrs in graph["nodes"].items():
        shape = shape_map.get(attrs.get("type", ""), "box")
        label = attrs.get("label", node_id).replace('"', '\\"')
        lines.append(f'  "{node_id}" [label="{label}" shape={shape}];')

    for edge in graph["edges"]:
        label = edge.get("label", "").replace('"', '\\"')
        lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')

    lines.append("}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def format_report(graph):
    nodes = graph["nodes"]
    edges = graph["edges"]

    type_counts = {}
    for attrs in nodes.values():
        t = attrs.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    edge_label_counts = {}
    for e in edges:
        lbl = e.get("label", "unknown")
        edge_label_counts[lbl] = edge_label_counts.get(lbl, 0) + 1

    lines = [
        "Graph Export Report",
        "=" * 40,
        "",
        f"  Total nodes:  {len(nodes)}",
        f"  Total edges:  {len(edges)}",
        "",
        "  Node types:",
    ]
    for t, c in sorted(type_counts.items()):
        lines.append(f"    {t:20s} {c}")

    lines.append("")
    lines.append("  Edge types:")
    for lbl, c in sorted(edge_label_counts.items()):
        lines.append(f"    {lbl:20s} {c}")
    lines.append("")

    return "\n".join(lines)


def load_events(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "events" in data:
            return data["events"]
        return [data]
    return [data]
