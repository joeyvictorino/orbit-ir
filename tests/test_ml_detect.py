"""Tests for ml_detect module."""

import json
import os
import tempfile
import math

from orbit_ir.ml_detect import compute_baseline, detect_anomalies, format_report, load_events


def test_compute_baseline_numeric():
    events = [{"value": 10}, {"value": 20}, {"value": 30}]
    bl = compute_baseline(events)
    assert "value" in bl["numeric"]
    assert bl["numeric"]["value"]["mean"] == 20.0
    assert bl["numeric"]["value"]["count"] == 3


def test_compute_baseline_categories():
    events = [
        {"type": "login"}, {"type": "login"}, {"type": "login"},
        {"type": "access"}, {"type": "access"},
        {"type": "error"},
    ]
    bl = compute_baseline(events)
    assert bl["categories"]["counts"]["login"] == 3
    assert bl["categories"]["counts"]["access"] == 2
    assert bl["categories"]["counts"]["error"] == 1


def test_compute_baseline_timing():
    events = [
        {"timestamp": 100}, {"timestamp": 200}, {"timestamp": 300},
    ]
    bl = compute_baseline(events)
    assert bl["timing"]["mean_interval"] == 100.0
    assert bl["timing"]["count"] == 2


def test_compute_baseline_empty():
    bl = compute_baseline([])
    assert bl["total_events"] == 0
    assert bl["numeric"] == {}


def test_compute_baseline_none_events():
    bl = compute_baseline([None, None])
    assert bl["total_events"] == 2
    assert bl["numeric"] == {}


def test_detect_anomalies_numeric():
    normal = [{"score": 10}, {"score": 11}, {"score": 9}, {"score": 10}, {"score": 10}]
    outlier = [{"score": 100}]
    all_events = normal + outlier
    result = detect_anomalies(all_events, z_threshold=2.0)
    anomaly_indices = [a["index"] for a in result["anomalies"]]
    assert 5 in anomaly_indices


def test_detect_anomalies_no_anomalies():
    events = [{"score": 10}, {"score": 10}, {"score": 10}]
    result = detect_anomalies(events)
    assert result["anomaly_count"] == 0
    assert result["severity"] == "none"


def test_detect_anomalies_timing():
    events = [
        {"timestamp": 100},
        {"timestamp": 200},
        {"timestamp": 300},
        {"timestamp": 400},
        {"timestamp": 500},
        {"timestamp": 5000},  # huge gap
    ]
    result = detect_anomalies(events, z_threshold=1.5)
    assert result["anomaly_count"] > 0


def test_detect_anomalies_category():
    events = (
        [{"type": "normal"}] * 50
        + [{"type": "rare"}] * 1
        + [{"type": "common"}] * 49
    )
    result = detect_anomalies(events, z_threshold=1.0)
    rare_flagged = any(
        any("rare" in r for r in a["reasons"])
        for a in result["anomalies"]
    )
    assert rare_flagged


def test_detect_anomalies_custom_threshold():
    events = [{"val": 10}, {"val": 10}, {"val": 10}, {"val": 15}]
    low = detect_anomalies(events, z_threshold=0.5)
    high = detect_anomalies(events, z_threshold=10.0)
    assert low["anomaly_count"] >= high["anomaly_count"]


def test_detect_anomalies_severity_levels():
    events = [{"val": i} for i in range(20)]
    events.append({"val": 9999})
    result = detect_anomalies(events, z_threshold=2.0)
    assert result["severity"] in ("none", "medium", "high", "critical")


def test_detect_anomalies_with_baseline():
    events = [{"score": 50}]
    baseline = {
        "numeric": {"score": {"mean": 10.0, "stddev": 2.0, "count": 100}},
        "categories": {"counts": {}, "mean_freq": 0, "stddev_freq": 0},
        "timing": {},
        "total_events": 100,
    }
    result = detect_anomalies(events, baseline=baseline, z_threshold=2.0)
    assert result["anomaly_count"] == 1


def test_format_report():
    events = [{"score": 10}, {"score": 10}, {"score": 100}]
    result = detect_anomalies(events)
    text = format_report(result)
    assert "Anomaly Detection Report" in text
    assert "Total events" in text


def test_format_report_no_anomalies():
    result = detect_anomalies([{"v": 1}, {"v": 1}])
    text = format_report(result)
    assert "Anomalies found:   0" in text
    assert "Severity:          none" in text


def test_format_report_many_anomalies():
    events = [{"val": i * 1000} for i in range(15)]
    result = detect_anomalies(events, z_threshold=0.1)
    text = format_report(result)
    if result["anomaly_count"] > 10:
        assert "more" in text


def test_load_events_list():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump([1, 2, 3], f)
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 3
    finally:
        os.unlink(path)


def test_load_events_dict():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump({"events": [{"a": 1}]}, f)
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 1
    finally:
        os.unlink(path)


def test_stddev_single_value():
    bl = compute_baseline([{"x": 5}])
    assert bl["numeric"]["x"]["stddev"] == 0.0


def test_string_events():
    events = ["login attempt", "login attempt", "login attempt"]
    bl = compute_baseline(events)
    assert bl["categories"]["counts"]["login attempt"] == 3


def test_mixed_events():
    events = [
        {"type": "scan", "severity": 3, "timestamp": 100},
        {"type": "scan", "severity": 3, "timestamp": 200},
        {"type": "scan", "severity": 3, "timestamp": 300},
        {"type": "scan", "severity": 3, "timestamp": 400},
        {"type": "scan", "severity": 3, "timestamp": 500},
        {"type": "scan", "severity": 3, "timestamp": 600},
        {"type": "exploit", "severity": 99, "timestamp": 5000},
    ]
    result = detect_anomalies(events, z_threshold=1.5)
    assert result["anomaly_count"] > 0
    assert any(
        any("severity" in r for r in a["reasons"])
        for a in result["anomalies"]
    )
