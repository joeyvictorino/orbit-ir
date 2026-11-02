"""Tests for evidence attribution analysis."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from orbit_ir.attribution import (
    attribute_evidence,
    build_attribution_chain,
    compute_confidence,
    format_attribution_text,
    load_and_attribute,
    summarize_attributions,
)


def test_compute_confidence_exact_match():
    ev = {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "exfil"}
    te = {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "exfil"}
    assert compute_confidence(ev, te) == 1.0


def test_compute_confidence_partial_match():
    ev = {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "exfil"}
    te = {"timestamp": "2024-01-01T10:05:00Z", "agent_id": "agent-1", "action": "scan"}
    conf = compute_confidence(ev, te)
    assert 0 < conf < 1.0


def test_compute_confidence_no_match():
    ev = {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "exfil"}
    te = {"timestamp": "2024-06-15T22:00:00Z", "agent_id": "agent-99", "action": "idle"}
    conf = compute_confidence(ev, te)
    assert conf == 0.0


def test_compute_confidence_empty():
    assert compute_confidence({}, {}) == 0.0


def test_build_attribution_chain():
    timeline = [
        {"id": "ev-1", "agent_id": "a1", "action": "scan", "timestamp": "T1"},
        {"id": "ev-2", "agent_id": "a2", "action": "move", "timestamp": "T2", "references": ["ev-1"]},
    ]
    chain = build_attribution_chain("ev-1", timeline)
    assert len(chain) == 2
    assert "a1" in chain[0]
    assert "ref" in chain[1]


def test_build_attribution_chain_no_match():
    timeline = [{"id": "ev-1", "agent_id": "a1", "action": "scan", "timestamp": "T1"}]
    chain = build_attribution_chain("ev-999", timeline)
    assert chain == []


def test_attribute_evidence_basic():
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "probe"},
        {"timestamp": "2024-01-01T11:00:00Z", "agent_id": "agent-2", "action": "exfil"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "probe"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "agent-2", "action": "exfil"},
    ]
    report = attribute_evidence(timeline, evidence)
    assert len(report.attributions) == 2
    assert len(report.unattributed) == 0
    assert len(report.sources) == 2


def test_attribute_evidence_unattributed():
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "probe"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-06-01T00:00:00Z", "agent_id": "unknown", "action": "?"},
    ]
    report = attribute_evidence(timeline, evidence, min_confidence=0.9)
    assert len(report.unattributed) == 1
    assert len(report.attributions) == 0


def test_attribute_evidence_empty():
    report = attribute_evidence([], [])
    assert len(report.attributions) == 0
    assert len(report.unattributed) == 0


def test_summarize_attributions():
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "probe"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "agent-1", "action": "probe"},
    ]
    report = attribute_evidence(timeline, evidence)
    summary = summarize_attributions(report)
    assert summary["attributed"] == 1
    assert summary["unattributed"] == 0
    assert summary["total_evidence"] == 1


def test_format_attribution_text():
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "system-daemon", "action": "log"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "system-daemon", "action": "log"},
    ]
    report = attribute_evidence(timeline, evidence)
    text = format_attribution_text(report)
    assert "Attribution Report" in text
    assert "system-daemon" in text
    assert "system" in text


def test_load_and_attribute(tmp_path: Path):
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan", "id": "t1"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "scan"},
    ]
    t_path = tmp_path / "timeline.json"
    e_path = tmp_path / "evidence.json"
    t_path.write_text(json.dumps(timeline))
    e_path.write_text(json.dumps(evidence))

    report = load_and_attribute(t_path, e_path)
    assert len(report.attributions) == 1


def test_confidence_distribution():
    timeline = [
        {"timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "probe"},
        {"timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    evidence = [
        {"id": "e1", "timestamp": "2024-01-01T10:00:00Z", "agent_id": "a1", "action": "probe"},
        {"id": "e2", "timestamp": "2024-01-01T11:00:00Z", "agent_id": "a2", "action": "exfil"},
    ]
    report = attribute_evidence(timeline, evidence)
    assert report.confidence_distribution["high"] == 2
