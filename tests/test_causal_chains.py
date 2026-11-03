"""Tests for evidence_chain module (causal chain builder)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.evidence_chain import (
    EvidenceChainBuilder,
    build_evidence_chains,
    format_evidence_chain_text,
    _extract_entities,
    _parse_ts,
    _severity_score,
)


@pytest.fixture
def chain_dir(tmp_path: Path) -> Path:
    events = [
        {"agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z", "type": "login", "resource": "db-server"},
        {"agent_id": "a1", "timestamp": "2026-01-01T00:01:00Z", "type": "query", "resource": "db-server"},
        {"agent_id": "a2", "timestamp": "2026-01-01T00:02:00Z", "type": "transfer", "resource": "db-server"},
        {"agent_id": "a2", "timestamp": "2026-01-01T00:03:00Z", "type": "exfil", "dst_ip": "10.0.0.5"},
        {"agent_id": "a3", "timestamp": "2026-01-01T01:00:00Z", "type": "scan", "resource": "web-server"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp_path


def test_extract_entities_agent():
    ev = {"agent_id": "a1", "resource": "db"}
    ents = _extract_entities(ev)
    assert "agent:a1" in ents
    assert "resource:db" in ents


def test_extract_entities_ip():
    ev = {"src_ip": "192.168.1.1"}
    ents = _extract_entities(ev)
    assert "ip:192.168.1.1" in ents


def test_extract_entities_path():
    ev = {"action": "read /etc/passwd"}
    ents = _extract_entities(ev)
    assert "path:/etc/passwd" in ents


def test_extract_entities_empty():
    ev = {}
    ents = _extract_entities(ev)
    assert len(ents) == 0


def test_parse_ts_iso():
    ev = {"timestamp": "2026-01-01T00:00:00Z"}
    ts = _parse_ts(ev)
    assert ts > 0


def test_parse_ts_numeric():
    ev = {"timestamp": 1700000000.0}
    ts = _parse_ts(ev)
    assert ts == 1700000000.0


def test_parse_ts_missing():
    ev = {}
    ts = _parse_ts(ev)
    assert ts == 0.0


def test_severity_score():
    assert _severity_score({"severity": "critical"}) == 1.0
    assert _severity_score({"severity": "low"}) == 0.25
    assert _severity_score({}) == 0.1


def test_build_chains(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    assert data["total_events"] == 5
    assert data["total_chains"] >= 1


def test_chain_shared_entities(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    chain1 = data["chains"][0]
    assert len(chain1["shared_entities"]) > 0
    has_db = any("db-server" in e for e in chain1["shared_entities"])
    assert has_db


def test_chain_event_count(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    total_in_chains = sum(c["event_count"] for c in data["chains"])
    assert total_in_chains <= data["total_events"]


def test_chain_risk_score(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    for chain in data["chains"]:
        assert 0 <= chain["risk_score"] <= 1.0


def test_chain_duration(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    chain1 = data["chains"][0]
    assert chain1["duration_seconds"] >= 0


def test_min_chain_length(chain_dir: Path):
    builder = build_evidence_chains(chain_dir, min_chain_length=5)
    data = builder.to_dict()
    for chain in data["chains"]:
        assert chain["event_count"] >= 5


def test_max_chains(chain_dir: Path):
    builder = build_evidence_chains(chain_dir, max_chains=1)
    data = builder.to_dict()
    assert len(data["chains"]) <= 1


def test_format_text(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    text = format_evidence_chain_text(builder.to_dict())
    assert "Evidence Chains" in text
    assert "Chain #1" in text


def test_empty_evidence(tmp_path: Path):
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    builder = build_evidence_chains(tmp_path)
    data = builder.to_dict()
    assert data["total_events"] == 0
    assert data["total_chains"] == 0


def test_json_output_structure(chain_dir: Path):
    builder = build_evidence_chains(chain_dir)
    data = builder.to_dict()
    assert "chains" in data
    for chain in data["chains"]:
        assert "chain_id" in chain
        assert "events" in chain
        assert "shared_entities" in chain
        assert "duration_seconds" in chain
        assert "risk_score" in chain


def test_single_event_no_chain(tmp_path: Path):
    events = [{"agent_id": "lonely", "timestamp": "2026-01-01T00:00:00Z", "type": "solo"}]
    f = tmp_path / "events.jsonl"
    f.write_text(json.dumps(events[0]), encoding="utf-8")
    builder = build_evidence_chains(tmp_path, min_chain_length=2)
    data = builder.to_dict()
    assert data["total_chains"] == 0
