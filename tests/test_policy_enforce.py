"""Tests for policy enforcement engine."""
import json
import tempfile
from pathlib import Path

from orbit_ir.policy_enforce import analyze, format_text, format_json


def _write(tmpdir, filename, data):
    path = Path(tmpdir) / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _policy(rules):
    return {"rules": rules}


def test_no_rules_no_events():
    with tempfile.TemporaryDirectory() as d:
        policy = Path(d) / "policy.json"
        policy.write_text("[]", encoding="utf-8")
        r = analyze(Path(d), policy)
        assert r.rules_loaded == 0
        assert r.events_evaluated == 0
        assert r.compliance_score == 1.0


def test_nonexistent_paths():
    r = analyze(Path("/nonexistent"), Path("/nonexistent/policy.json"))
    assert r.rules_loaded == 0
    assert r.events_evaluated == 0


def test_no_violations():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "low", "agent": "a1"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
        ]))
        r = analyze(Path(d), policy)
        assert r.rules_loaded == 1
        assert r.events_evaluated == 1
        assert len(r.violations) == 0
        assert r.compliance_score == 1.0


def test_single_violation():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "critical", "agent": "a1"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "no-critical", "description": "No critical events allowed",
             "field": "severity", "operator": "eq", "value": "critical",
             "severity": "high"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1
        assert r.violations[0].rule_id == "no-critical"
        assert r.compliance_score == 0.0


def test_multiple_rules():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "critical", "score": 95},
            {"detector": "d2", "severity": "low", "score": 30},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
            {"id": "r2", "field": "score", "operator": "gt", "value": 90},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 2
        assert "r1" in r.rules_triggered
        assert "r2" in r.rules_triggered


def test_contains_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "message": "found suspicious activity"},
            {"detector": "d2", "message": "normal operation"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "message", "operator": "contains",
             "value": "suspicious"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_not_contains_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "status": "unreviewed"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "status", "operator": "not_contains",
             "value": "reviewed"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 0


def test_exists_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "remediation": "patched"},
            {"detector": "d2"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "remediation", "operator": "exists"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_not_exists_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1"},
            {"detector": "d2", "remediation": "done"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "remediation", "operator": "not_exists",
             "severity": "medium"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1
        assert r.violations[0].severity == "medium"


def test_numeric_operators():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"score": 80}, {"score": 50}, {"score": 100},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "high-score", "field": "score", "operator": "gte", "value": 80},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 2


def test_lt_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"confidence": 0.3}, {"confidence": 0.9},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "low-conf", "field": "confidence", "operator": "lt", "value": 0.5},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_nested_field():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "metadata": {"risk": "high"}},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "metadata.risk", "operator": "eq", "value": "high"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_ne_operator():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"status": "open"}, {"status": "closed"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "status", "operator": "ne", "value": "closed"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_compliance_score_partial():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"severity": "critical"},
            {"severity": "low"},
            {"severity": "low"},
            {"severity": "low"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
        ]))
        r = analyze(Path(d), policy)
        assert r.compliance_score == 0.75


def test_violations_by_severity():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"type": "bad"}, {"type": "bad"},
        ])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "type", "operator": "eq", "value": "bad",
             "severity": "critical"},
        ]))
        r = analyze(Path(d), policy)
        assert r.violations_by_severity.get("critical") == 2


def test_dict_with_events_key():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "data.json", {
            "events": [{"severity": "critical"}],
        })
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
        ]))
        r = analyze(Path(d), policy)
        assert len(r.violations) == 1


def test_skips_non_json():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "readme.txt").write_text("not json")
        _write(d, "events.json", [{"severity": "high"}])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "high"},
        ]))
        r = analyze(Path(d), policy)
        assert r.events_evaluated == 1


def test_format_text_empty():
    r = analyze(Path("/nonexistent"), Path("/nonexistent/p.json"))
    text = format_text(r)
    assert "Policy Enforcement" in text
    assert "No policy rules" in text


def test_format_text_with_data():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [{"severity": "critical", "detector": "d1"}])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
        ]))
        r = analyze(Path(d), policy)
        text = format_text(r)
        assert "Violations" in text
        assert "Compliance score" in text


def test_format_json_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [{"severity": "critical"}])
        policy = _write(d, "policy.json", _policy([
            {"id": "r1", "field": "severity", "operator": "eq", "value": "critical"},
        ]))
        r = analyze(Path(d), policy)
        data = json.loads(format_json(r))
        assert "violations" in data
        assert data["rules_loaded"] == 1
        assert data["violations_count"] == 1
