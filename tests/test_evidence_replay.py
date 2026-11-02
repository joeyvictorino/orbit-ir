"""Tests for evidence replay simulator."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.evidence_replay import analyze, format_text, format_json, ReplayReport


def _write_events(tmpdir, filename, data):
    path = Path(tmpdir) / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        r = analyze(Path(d))
        assert r.total == 0
        assert r.fidelity_score == 1.0
        assert r.events == []


def test_nonexistent_dir():
    r = analyze(Path("/nonexistent/path"))
    assert r.total == 0


def test_single_event():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        assert r.total == 1
        assert r.in_order_count == 1
        assert r.fidelity_score == 1.0
        assert len(r.anomalies) == 0


def test_ordered_events():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:02:00Z", "agent": "a1", "action": "write"},
            {"timestamp": "2025-01-01T00:03:00Z", "agent": "a2", "action": "exec"},
        ])
        r = analyze(Path(d))
        assert r.total == 3
        assert r.in_order_count == 3
        assert r.fidelity_score == 1.0


def test_missing_timestamp():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:02:00Z", "agent": "a2", "action": "write"},
        ])
        r = analyze(Path(d))
        assert r.total == 2
        anomaly_kinds = [a.kind for a in r.anomalies]
        assert "missing_timestamp" in anomaly_kinds


def test_duplicate_detection():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        anomaly_kinds = [a.kind for a in r.anomalies]
        assert "duplicate" in anomaly_kinds


def test_dict_with_events_key():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "data.json", {
            "events": [
                {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
                {"timestamp": "2025-01-01T00:02:00Z", "agent": "a2", "action": "write"},
            ]
        })
        r = analyze(Path(d))
        assert r.total == 2


def test_single_dict_event():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "single.json", {
            "timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read",
        })
        r = analyze(Path(d))
        assert r.total == 1


def test_alternative_field_names():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"time": "2025-01-01T00:01:00Z", "agent_id": "a1", "type": "read"},
            {"time": "2025-01-01T00:02:00Z", "agent_id": "a2", "kind": "write"},
        ])
        r = analyze(Path(d))
        assert r.total == 2
        assert r.events[0].agent == "a1"


def test_skips_non_json():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "readme.txt").write_text("not json")
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        assert r.total == 1


def test_skips_invalid_json():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "bad.json").write_text("{invalid json")
        _write_events(d, "good.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        assert r.total == 1


def test_format_text_empty():
    r = ReplayReport(events=[], total=0, fidelity_score=1.0)
    text = format_text(r)
    assert "Evidence Replay" in text
    assert "No events" in text


def test_format_text_with_data():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:02:00Z", "agent": "a2", "action": "write"},
        ])
        r = analyze(Path(d))
        text = format_text(r)
        assert "Evidence Replay" in text
        assert "Total events" in text
        assert "Fidelity score" in text


def test_format_json_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        data = json.loads(format_json(r))
        assert "fidelity_score" in data
        assert "event_count" in data
        assert data["event_count"] == 1


def test_format_text_with_anomalies():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        r = analyze(Path(d))
        text = format_text(r)
        assert "Anomalies" in text


def test_multiple_files():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "a.json", [
            {"timestamp": "2025-01-01T00:01:00Z", "agent": "a1", "action": "read"},
        ])
        _write_events(d, "b.json", [
            {"timestamp": "2025-01-01T00:02:00Z", "agent": "a2", "action": "write"},
        ])
        r = analyze(Path(d))
        assert r.total == 2
        assert r.events[0].source_file == "a.json"
        assert r.events[1].source_file == "b.json"
