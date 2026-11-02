"""Tests for the STRIDE threat model builder."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.threat_model import (
    analyze,
    format_text,
    format_json,
    _detect_threats,
    _has_injection_pattern,
    ThreatModelReport,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {"agent_id": "agent-1", "action": "read", "resource": "/etc/config.yaml", "timestamp": "2024-01-01T00:00:01Z"},
        {"agent_id": "agent-1", "action": "write", "resource": "/etc/config.yaml", "timestamp": "2024-01-01T00:00:02Z"},
        {"agent_id": "agent-1", "action": "read", "resource": "/secrets/api-key", "timestamp": "2024-01-01T00:00:03Z"},
        {"agent_id": "agent-2", "action": "execute", "resource": "sudo chmod 777 /tmp", "timestamp": "2024-01-01T00:00:04Z"},
        {"agent_id": "agent-2", "action": "read", "resource": "/var/data/file1", "timestamp": "2024-01-01T00:00:05Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    return tmp_path


def test_analyze_empty(empty_dir: Path) -> None:
    report = analyze(empty_dir)
    assert report.summary.total_threats == 0
    assert report.summary.total_agents == 0


def test_analyze_basic(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    assert report.summary.total_agents == 2
    assert report.summary.total_threats > 0


def test_detects_config_tampering(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    tampering = [t for t in report.threats if t.category == "tampering"]
    assert len(tampering) > 0
    assert any(t.signal == "config_modify" for t in tampering)


def test_detects_credential_access(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    disclosure = [t for t in report.threats if t.category == "info_disclosure"]
    assert len(disclosure) > 0
    assert any(t.signal == "credential_access" for t in disclosure)


def test_detects_privilege_escalation(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    elevation = [t for t in report.threats if t.category == "elevation"]
    assert len(elevation) > 0


def test_injection_pattern() -> None:
    assert _has_injection_pattern({"parameters": "ls && cat /etc/passwd"})
    assert _has_injection_pattern({"args": "echo $(whoami)"})
    assert not _has_injection_pattern({"parameters": "normal argument"})


def test_detect_threats_identity_change() -> None:
    events = [
        {"agent_id": "agent-1", "identity": "user-a"},
        {"agent_id": "agent-1", "identity": "user-b"},
    ]
    threats = _detect_threats("agent-1", events)
    spoofing = [t for t in threats if t.category == "spoofing"]
    assert len(spoofing) > 0


def test_format_text(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    text = format_text(report)
    assert "STRIDE Threat Model Report" in text
    assert "Total threats:" in text


def test_format_json(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    output = format_json(report)
    data = json.loads(output)
    assert "threats" in data
    assert "categories" in data
    assert "summary" in data


def test_severity_ordering(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    if len(report.threats) >= 2:
        severities = [t.severity for t in report.threats]
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        ranks = [rank.get(s, 0) for s in severities]
        assert ranks == sorted(ranks, reverse=True)


def test_categories_populated(evidence_dir: Path) -> None:
    report = analyze(evidence_dir)
    assert len(report.categories) > 0
    for cat in report.categories:
        assert cat.category in (
            "spoofing", "tampering", "repudiation",
            "info_disclosure", "denial_of_service", "elevation",
        )
        assert cat.threat_count > 0
