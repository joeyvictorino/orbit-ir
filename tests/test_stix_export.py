"""Tests for STIX 2.1 export."""
import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.stix_export import STIXExporter, _deterministic_uuid, export_stix


def _write_events(events: list[dict], tmp_path: Path) -> Path:
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return f


def test_empty_bundle():
    exp = STIXExporter([])
    bundle = exp.to_stix_bundle()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"] == []


def test_threat_actor_from_agent():
    events = [{"agent_id": "agent-1", "action": "read_file", "timestamp": "2024-01-01T00:00:00Z"}]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(actors) == 1
    assert actors[0]["name"] == "agent-1"
    assert actors[0]["spec_version"] == "2.1"


def test_attack_pattern_from_technique():
    events = [{"agent_id": "a1", "technique": "credential_reuse", "technique_id": "T1078"}]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(patterns) == 1
    assert patterns[0]["name"] == "credential_reuse"
    assert patterns[0]["external_references"][0]["external_id"] == "T1078"


def test_observed_data_per_event():
    events = [
        {"agent_id": "a1", "action": "read", "timestamp": "2024-01-01T00:00:00Z", "id": "e1"},
        {"agent_id": "a1", "action": "write", "timestamp": "2024-01-01T00:01:00Z", "id": "e2"},
    ]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert len(obs) == 2


def test_relationship_uses():
    events = [{"agent_id": "a1", "technique": "lateral_movement"}]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    assert rels[0]["relationship_type"] == "uses"


def test_indicator_extraction():
    events = [{"agent_id": "a1", "target": "192.168.1.100", "timestamp": "2024-01-01T00:00:00Z"}]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=True)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert any("192.168.1.100" in i["pattern"] for i in indicators)


def test_no_indicators_flag():
    events = [{"agent_id": "a1", "target": "192.168.1.100"}]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 0


def test_deterministic_uuid():
    u1 = _deterministic_uuid("ns", "a", "b")
    u2 = _deterministic_uuid("ns", "a", "b")
    u3 = _deterministic_uuid("ns", "a", "c")
    assert u1 == u2
    assert u1 != u3


def test_dedup_agents():
    events = [
        {"agent_id": "a1", "action": "read"},
        {"agent_id": "a1", "action": "write"},
    ]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(actors) == 1


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "action": "read"},
        {"agent_id": "a2", "action": "write"},
    ]
    exp = STIXExporter(events)
    bundle = exp.to_stix_bundle(include_indicators=False)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(actors) == 2
    names = {a["name"] for a in actors}
    assert names == {"a1", "a2"}


def test_to_json_valid():
    events = [{"agent_id": "a1", "technique": "recon"}]
    exp = STIXExporter(events)
    text = exp.to_json(include_indicators=False)
    data = json.loads(text)
    assert data["type"] == "bundle"


def test_load_from_file(tmp_path):
    events = [{"agent_id": "a1", "action": "scan", "id": "e1"}]
    f = _write_events(events, tmp_path)
    exp = STIXExporter()
    exp.load_events(f)
    bundle = exp.to_stix_bundle(include_indicators=False)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(actors) == 1


def test_load_from_directory(tmp_path):
    events = [{"agent_id": "a1", "id": "e1"}, {"agent_id": "a2", "id": "e2"}]
    (tmp_path / "ev.jsonl").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    exp = STIXExporter()
    exp.load_events(tmp_path)
    bundle = exp.to_stix_bundle(include_indicators=False)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    assert len(actors) == 2


def test_export_stix_helper(tmp_path):
    events = [{"agent_id": "a1", "technique": "recon", "id": "e1"}]
    f = _write_events(events, tmp_path)
    exp = export_stix(f, include_indicators=False)
    assert hasattr(exp, "_bundle")
