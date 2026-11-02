"""Tests for SARIF v2.1.0 output."""

from __future__ import annotations

import json

from orbit_ir.sarif import findings_to_sarif, SARIF_SCHEMA


def _make_finding(**overrides):
    base = {
        "finding_id": "f-001",
        "tool_call_id": "tc-001",
        "agent_id_transcript": "agent-a",
        "agent_id_control": "agent-a",
        "trace_id_transcript": "tr-1",
        "trace_id_control": "tr-1",
        "reasons": ["tool-name-mismatch"],
        "mitre_techniques": [{"id": "T1036", "name": "Masquerading"}],
        "transcript_source": "transcripts.jsonl",
        "transcript_line": [10],
        "control_source": "control_plane.jsonl",
        "control_line": [42],
        "claimed_tool": "read_file",
        "actual_tool": "exec_command",
        "effect": "file_write",
        "confidence": "HIGH",
        "confidence_score": 0.95,
    }
    base.update(overrides)
    return base


def test_sarif_structure():
    sarif = findings_to_sarif([_make_finding()])
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "orbit-ir"
    assert "version" in run["tool"]["driver"]


def test_sarif_finding_maps_correctly():
    finding = _make_finding()
    sarif = findings_to_sarif([finding])
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "orbit-ir/tool-name-mismatch"
    assert r["level"] == "error"
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "control_plane.jsonl"
    assert loc["region"]["startLine"] == 42
    props = r["properties"]
    assert props["finding_id"] == "f-001"
    assert props["confidence"] == "HIGH"
    assert "MITRE:T1036" in props["tags"]


def test_sarif_multiple_reasons():
    finding = _make_finding(reasons=["tool-name-mismatch", "agent-id-mismatch"])
    sarif = findings_to_sarif([finding])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "orbit-ir/tool-name-mismatch" in rule_ids
    assert "orbit-ir/agent-id-mismatch" in rule_ids


def test_sarif_lateral_movement():
    lm = [
        {
            "agent_id": "agent-x",
            "resource": "/data/private.db",
            "resource_owner": "agent-y",
            "effect": "read",
            "tool_call_id": "tc-lat-1",
            "source_line": 99,
        }
    ]
    sarif = findings_to_sarif([], lateral_movement=lm)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "orbit-ir/lateral-resource-access"
    assert r["level"] == "error"
    assert "agent-x" in r["message"]["text"]
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 99


def test_sarif_empty_findings():
    sarif = findings_to_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_is_valid_json():
    sarif = findings_to_sarif([_make_finding()])
    text = json.dumps(sarif)
    parsed = json.loads(text)
    assert parsed["version"] == "2.1.0"


def test_sarif_unknown_reason():
    finding = _make_finding(reasons=["some-future-reason"])
    sarif = findings_to_sarif([finding])
    results = sarif["runs"][0]["results"]
    assert results[0]["ruleId"] == "orbit-ir/unknown"
