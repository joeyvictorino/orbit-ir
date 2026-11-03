"""Tests for signal-to-noise analysis."""
import json
import tempfile
from pathlib import Path

from orbit_ir.signal_noise import analyze, format_text, format_json


def _write(tmpdir, filename, data):
    path = Path(tmpdir) / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        r = analyze(Path(d))
        assert r.total_events == 0
        assert r.signal_count == 0


def test_nonexistent_dir():
    r = analyze(Path("/nonexistent"))
    assert r.total_events == 0


def test_signal_event():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "critical",
             "summary": "unauthorized access detected via credential theft"},
        ])
        r = analyze(Path(d))
        assert r.total_events == 1
        assert r.signal_count == 1
        assert r.signal_ratio > 0


def test_noise_event():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "info",
             "summary": "routine health_check heartbeat ping"},
        ])
        r = analyze(Path(d))
        assert r.total_events == 1
        assert r.noise_count == 1


def test_mixed_events():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "critical",
             "summary": "injection exploit detected"},
            {"detector": "d2", "severity": "info",
             "summary": "routine heartbeat"},
            {"detector": "d3", "severity": "medium",
             "summary": "normal operation"},
        ])
        r = analyze(Path(d))
        assert r.total_events == 3
        assert r.signal_count >= 1
        assert r.noise_count >= 0


def test_severity_distribution():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "low"},
        ])
        r = analyze(Path(d))
        assert r.severity_distribution.get("critical") == 1
        assert r.severity_distribution.get("high") == 1
        assert r.severity_distribution.get("low") == 1


def test_repetitive_events_penalized():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"detector": "d1", "type": "heartbeat", "severity": "info"}
        ] * 10
        _write(d, "events.json", events)
        r = analyze(Path(d))
        assert r.noise_count >= 5


def test_evidence_boosts_signal():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"detector": "d1", "severity": "medium",
             "summary": "suspicious activity",
             "evidence": {"payload": "test"},
             "location": "/api/endpoint"},
        ])
        r = analyze(Path(d))
        assert r.total_events == 1
        top = r.top_signals
        if top:
            assert top[0].signal_score > 0.3


def test_top_signals_capped():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"detector": f"d{i}", "severity": "critical",
             "summary": f"unauthorized breach attempt {i}"}
            for i in range(30)
        ]
        _write(d, "events.json", events)
        r = analyze(Path(d))
        assert len(r.top_signals) <= 20


def test_noise_patterns():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"detector": "health", "type": "heartbeat", "severity": "info"}
        ] * 5 + [
            {"detector": "d1", "severity": "critical",
             "summary": "exploit detected"}
        ]
        _write(d, "events.json", events)
        r = analyze(Path(d))
        assert len(r.noise_patterns) > 0


def test_dict_with_events_key():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "data.json", {
            "events": [
                {"severity": "critical", "summary": "unauthorized access"}
            ],
        })
        r = analyze(Path(d))
        assert r.total_events == 1


def test_format_text_empty():
    r = analyze(Path("/nonexistent"))
    text = format_text(r)
    assert "Signal-to-Noise" in text
    assert "No events" in text


def test_format_text_with_data():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"severity": "critical", "detector": "d1",
             "summary": "attack detected"},
        ])
        r = analyze(Path(d))
        text = format_text(r)
        assert "Signal events" in text
        assert "Signal ratio" in text


def test_format_json_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"severity": "high", "summary": "suspicious lateral movement"},
        ])
        r = analyze(Path(d))
        data = json.loads(format_json(r))
        assert "total_events" in data
        assert "signal_count" in data
        assert "top_signals" in data


def test_skips_non_json():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "readme.txt").write_text("not json")
        _write(d, "events.json", [{"severity": "high"}])
        r = analyze(Path(d))
        assert r.total_events == 1


def test_signal_ratio_bounds():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "events.json", [
            {"severity": "critical", "summary": "unauthorized injection exploit"},
        ])
        r = analyze(Path(d))
        assert 0.0 <= r.signal_ratio <= 1.0
