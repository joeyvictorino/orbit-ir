"""Tests for the intent classification module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.intent import (
    IntentClassifier,
    classify_intents,
    format_intent_text,
    format_intent_json,
    _classify_event,
    _action_lower,
    _resource_lower,
    _match_set,
    INTENT_CATEGORIES,
)


@pytest.fixture
def recon_dir(tmp_path: Path) -> Path:
    events = [
        {"agent_id": "scanner", "actual_tool": "list_hosts", "resource": "network/hosts", "timestamp": "2026-01-15T10:00:00Z"},
        {"agent_id": "scanner", "actual_tool": "scan_ports", "resource": "network/ports", "timestamp": "2026-01-15T10:01:00Z"},
        {"agent_id": "scanner", "actual_tool": "enumerate_users", "resource": "iam/users", "timestamp": "2026-01-15T10:02:00Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def mixed_dir(tmp_path: Path) -> Path:
    events = [
        {"agent_id": "attacker", "actual_tool": "scan_ports", "resource": "hosts", "timestamp": "2026-01-15T10:00:00Z"},
        {"agent_id": "attacker", "actual_tool": "read_config", "resource": "credentials", "timestamp": "2026-01-15T10:01:00Z"},
        {"agent_id": "attacker", "actual_tool": "create_role", "resource": "roles/admin", "effect": "privilege-escalated", "timestamp": "2026-01-15T10:02:00Z"},
        {"agent_id": "attacker", "actual_tool": "upload", "resource": "s3://exfil-bucket", "timestamp": "2026-01-15T10:03:00Z"},
        {"agent_id": "attacker", "actual_tool": "delete", "resource": "logs/audit.log", "timestamp": "2026-01-15T10:04:00Z"},
        {"agent_id": "worker", "actual_tool": "process_data", "resource": "internal/pipeline", "timestamp": "2026-01-15T10:00:00Z"},
        {"agent_id": "worker", "actual_tool": "update_record", "resource": "internal/db", "timestamp": "2026-01-15T10:01:00Z"},
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


def test_classify_recon(recon_dir: Path):
    report = classify_intents(recon_dir)
    assert report.total_agents == 1
    cls = report.classifications[0]
    assert cls.agent_id == "scanner"
    assert cls.primary_intent == "reconnaissance"
    assert cls.confidence > 0.5


def test_classify_mixed_agents(mixed_dir: Path):
    report = classify_intents(mixed_dir)
    assert report.total_agents == 2
    by_agent = {c.agent_id: c for c in report.classifications}
    assert "attacker" in by_agent
    assert "worker" in by_agent
    assert by_agent["worker"].primary_intent == "legitimate"


def test_agent_filter(mixed_dir: Path):
    report = classify_intents(mixed_dir, agent_id="attacker")
    assert report.total_agents == 1
    assert report.classifications[0].agent_id == "attacker"


def test_min_confidence_filter(mixed_dir: Path):
    report = classify_intents(mixed_dir, min_confidence=0.9)
    for cls in report.classifications:
        for sig in cls.signals:
            assert sig.confidence >= 0.9


def test_classify_event_recon():
    ev = {"actual_tool": "scan_ports", "resource": "network/hosts"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "reconnaissance" in cats


def test_classify_event_data_collection():
    ev = {"actual_tool": "read_config", "resource": "credentials/db"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "data_collection" in cats


def test_classify_event_exploitation():
    ev = {"actual_tool": "create_role", "effect": "privilege-escalated"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "exploitation" in cats


def test_classify_event_exfiltration():
    ev = {"actual_tool": "upload", "resource": "s3://bucket"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "exfiltration" in cats


def test_classify_event_cleanup():
    ev = {"actual_tool": "delete", "resource": "logs/audit.log"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "cleanup" in cats


def test_classify_event_legitimate():
    ev = {"actual_tool": "process_data", "resource": "internal/pipeline"}
    signals = _classify_event(ev)
    assert signals[0].category == "legitimate"


def test_intent_scores(recon_dir: Path):
    report = classify_intents(recon_dir)
    cls = report.classifications[0]
    assert "reconnaissance" in cls.intent_scores
    assert cls.intent_scores["reconnaissance"] > 0


def test_summary(mixed_dir: Path):
    report = classify_intents(mixed_dir)
    assert isinstance(report.summary, dict)
    total = sum(report.summary.values())
    assert total == report.total_agents


def test_format_text(mixed_dir: Path):
    report = classify_intents(mixed_dir)
    text = format_intent_text(report)
    assert "Intent Classification Report" in text
    assert "attacker" in text
    assert "worker" in text


def test_format_json(mixed_dir: Path):
    report = classify_intents(mixed_dir)
    output = format_intent_json(report)
    parsed = json.loads(output)
    assert parsed["total_agents"] == 2
    assert len(parsed["classifications"]) == 2


def test_empty_evidence(tmp_path: Path):
    report = classify_intents(tmp_path)
    assert report.total_agents == 0
    assert report.classifications == []


def test_classifier_class(recon_dir: Path):
    classifier = IntentClassifier(min_confidence=0.5)
    report = classifier.classify(recon_dir)
    assert report.total_agents == 1


def test_all_categories_present():
    assert "reconnaissance" in INTENT_CATEGORIES
    assert "data_collection" in INTENT_CATEGORIES
    assert "exploitation" in INTENT_CATEGORIES
    assert "exfiltration" in INTENT_CATEGORIES
    assert "cleanup" in INTENT_CATEGORIES
    assert "legitimate" in INTENT_CATEGORIES


def test_action_lower():
    assert _action_lower({"actual_tool": "ScanPorts"}) == "scanports"
    assert _action_lower({"tool_name": "ReadFile"}) == "readfile"
    assert _action_lower({}) == ""


def test_resource_lower():
    assert _resource_lower({"resource": "IAM/Users"}) == "iam/users"
    assert _resource_lower({"endpoint": "/API/secrets"}) == "/api/secrets"


def test_match_set():
    assert _match_set("scan_ports", frozenset({"scan"})) is True
    assert _match_set("process_data", frozenset({"scan"})) is False


def test_high_confidence_exploitation():
    ev = {"actual_tool": "create_role", "effect": "role-modified"}
    signals = _classify_event(ev)
    exploit_signals = [s for s in signals if s.category == "exploitation"]
    assert len(exploit_signals) > 0
    assert exploit_signals[0].confidence >= 0.8


def test_high_confidence_recon_both():
    ev = {"actual_tool": "enumerate_hosts", "resource": "network/endpoints"}
    signals = _classify_event(ev)
    recon_signals = [s for s in signals if s.category == "reconnaissance"]
    assert len(recon_signals) > 0
    assert recon_signals[0].confidence >= 0.7


def test_json_roundtrip(mixed_dir: Path):
    report = classify_intents(mixed_dir)
    output = format_intent_json(report)
    parsed = json.loads(output)
    assert "classifications" in parsed
    for cls in parsed["classifications"]:
        assert "primary_intent" in cls
        assert "confidence" in cls
        assert "intent_scores" in cls


def test_multiple_signals_per_event():
    ev = {"actual_tool": "read_config", "resource": "credentials/database"}
    signals = _classify_event(ev)
    cats = {s.category for s in signals}
    assert "data_collection" in cats
    assert len(signals) >= 1
