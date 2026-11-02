"""Tests for cross-detector anomaly correlation."""
import json
import tempfile
from pathlib import Path

from orbit_ir.anomaly_correlate import analyze, format_text, format_json, CorrelationReport


def _write_events(tmpdir, filename, data):
    path = Path(tmpdir) / filename
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        r = analyze(Path(d))
        assert r.detectors_analyzed == 0
        assert r.total_anomalies == 0
        assert r.pairs == []
        assert r.clusters == []


def test_nonexistent_dir():
    r = analyze(Path("/nonexistent/path"))
    assert r.detectors_analyzed == 0


def test_single_detector():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1", "timestamp": "2025-01-01T00:01:00Z"},
            {"detector": "d1", "agent": "a2", "timestamp": "2025-01-01T00:02:00Z"},
        ])
        r = analyze(Path(d))
        assert r.detectors_analyzed == 1
        assert r.total_anomalies == 2
        assert len(r.pairs) == 0


def test_two_detectors_no_overlap():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1", "timestamp": "2025-01-01T00:01:00Z"},
            {"detector": "d2", "agent": "a2", "timestamp": "2025-01-01T00:02:00Z"},
        ])
        r = analyze(Path(d))
        assert r.detectors_analyzed == 2
        assert len(r.pairs) == 1
        assert r.pairs[0].correlation == 0.0
        assert r.pairs[0].co_occurrences == 0


def test_two_detectors_full_overlap():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1", "timestamp": "2025-01-01T00:01:00Z"},
            {"detector": "d2", "agent": "a1", "timestamp": "2025-01-01T00:02:00Z"},
        ])
        r = analyze(Path(d))
        assert r.detectors_analyzed == 2
        assert len(r.pairs) == 1
        assert r.pairs[0].correlation == 1.0
        assert r.pairs[0].co_occurrences == 1


def test_partial_overlap():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1", "timestamp": "2025-01-01T00:01:00Z"},
            {"detector": "d1", "agent": "a2", "timestamp": "2025-01-01T00:02:00Z"},
            {"detector": "d2", "agent": "a1", "timestamp": "2025-01-01T00:03:00Z"},
            {"detector": "d2", "agent": "a3", "timestamp": "2025-01-01T00:04:00Z"},
        ])
        r = analyze(Path(d))
        assert r.pairs[0].co_occurrences == 1
        assert 0.3 < r.pairs[0].correlation < 0.4


def test_strongest_pair_reported():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
        ])
        r = analyze(Path(d))
        assert r.strongest_pair is not None
        assert "d1" in r.strongest_pair
        assert "d2" in r.strongest_pair


def test_no_strongest_pair_when_no_correlation():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a2"},
        ])
        r = analyze(Path(d))
        assert r.strongest_pair is None


def test_cluster_detection():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
            {"detector": "d3", "agent": "a1"},
        ])
        r = analyze(Path(d))
        assert len(r.clusters) >= 1
        assert "a1" in r.clusters[0].agents
        assert len(r.clusters[0].detectors) >= 2


def test_no_clusters_single_detector_per_agent():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a2"},
            {"detector": "d3", "agent": "a3"},
        ])
        r = analyze(Path(d))
        assert len(r.clusters) == 0


def test_alternative_field_names():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"source": "scanner-a", "agent_id": "a1"},
            {"source": "scanner-b", "agent_id": "a1"},
        ])
        r = analyze(Path(d))
        assert r.detectors_analyzed == 2
        assert r.pairs[0].correlation == 1.0


def test_dict_with_events_key():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "data.json", {
            "events": [
                {"detector": "d1", "agent": "a1"},
                {"detector": "d2", "agent": "a1"},
            ]
        })
        r = analyze(Path(d))
        assert r.detectors_analyzed == 2


def test_dict_with_findings_key():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "data.json", {
            "findings": [
                {"detector": "d1", "agent": "a1"},
                {"detector": "d2", "agent": "a1"},
            ]
        })
        r = analyze(Path(d))
        assert r.detectors_analyzed == 2


def test_format_text_empty():
    r = CorrelationReport(pairs=[], detectors_analyzed=0, total_anomalies=0, clusters=[])
    text = format_text(r)
    assert "Cross-Detector Anomaly Correlation" in text
    assert "No anomaly events" in text


def test_format_text_with_data():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
        ])
        r = analyze(Path(d))
        text = format_text(r)
        assert "Cross-Detector Anomaly Correlation" in text
        assert "Detectors analyzed" in text
        assert "Detector Pairs" in text


def test_format_text_with_clusters():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
            {"detector": "d3", "agent": "a1"},
        ])
        r = analyze(Path(d))
        text = format_text(r)
        assert "Anomaly Clusters" in text


def test_format_json_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
        ])
        r = analyze(Path(d))
        data = json.loads(format_json(r))
        assert "pairs" in data
        assert "detectors_analyzed" in data
        assert "clusters" in data
        assert data["detectors_analyzed"] == 2


def test_pairs_sorted_by_correlation():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d1", "agent": "a2"},
            {"detector": "d2", "agent": "a1"},
            {"detector": "d2", "agent": "a2"},
            {"detector": "d3", "agent": "a3"},
        ])
        r = analyze(Path(d))
        assert len(r.pairs) >= 2
        for i in range(len(r.pairs) - 1):
            assert r.pairs[i].correlation >= r.pairs[i + 1].correlation


def test_skips_non_json():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "readme.txt").write_text("not json")
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
        ])
        r = analyze(Path(d))
        assert r.total_anomalies == 1


def test_three_detectors():
    with tempfile.TemporaryDirectory() as d:
        _write_events(d, "events.json", [
            {"detector": "d1", "agent": "a1"},
            {"detector": "d2", "agent": "a1"},
            {"detector": "d3", "agent": "a2"},
        ])
        r = analyze(Path(d))
        assert r.detectors_analyzed == 3
        assert len(r.pairs) == 3
