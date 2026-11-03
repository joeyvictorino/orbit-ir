"""Tests for orbit_ir.outlier."""

import json
from pathlib import Path

from orbit_ir.outlier import detect_outliers, format_outlier_text, load_and_detect


def test_empty_events():
    result = detect_outliers([])
    assert result["total_events"] == 0
    assert result["agent_outliers"] == []
    assert result["type_outliers"] == []
    assert result["burst_windows"] == []


def test_no_outliers_uniform():
    events = [
        {"agent_id": f"a{i}", "event_type": "msg", "timestamp": f"2025-01-01T{i:02d}:00:00Z"}
        for i in range(10)
    ]
    result = detect_outliers(events, z_threshold=2.0)
    assert result["summary"]["agent_outlier_count"] == 0


def test_agent_outlier_high():
    events = []
    for i in range(100):
        events.append({"agent_id": "noisy", "timestamp": "2025-01-01T10:00:00Z"})
    for i in range(5):
        events.append({"agent_id": f"quiet_{i}", "timestamp": "2025-01-01T11:00:00Z"})
    result = detect_outliers(events, z_threshold=1.5)
    agent_keys = [o["key"] for o in result["agent_outliers"]]
    assert "noisy" in agent_keys
    assert result["agent_outliers"][0]["direction"] == "high"


def test_burst_detection():
    events = []
    for i in range(50):
        events.append({"agent_id": "a1", "timestamp": "2025-01-01T03:00:00Z"})
    for h in range(1, 24):
        if h != 3:
            events.append({"agent_id": "a1", "timestamp": f"2025-01-01T{h:02d}:00:00Z"})
    result = detect_outliers(events, z_threshold=2.0)
    burst_keys = [o["key"] for o in result["burst_windows"]]
    assert "2025-01-01T03" in burst_keys


def test_z_threshold_parameter():
    events = []
    for i in range(20):
        events.append({"agent_id": "big", "timestamp": "2025-01-01T10:00:00Z"})
    for i in range(3):
        events.append({"agent_id": f"small_{i}", "timestamp": "2025-01-01T11:00:00Z"})
    result_low = detect_outliers(events, z_threshold=0.5)
    result_high = detect_outliers(events, z_threshold=5.0)
    assert result_low["summary"]["agent_outlier_count"] >= result_high["summary"]["agent_outlier_count"]


def test_text_output():
    events = []
    for i in range(50):
        events.append({"agent_id": "outlier_agent", "event_type": "flood", "timestamp": "2025-01-01T10:00:00Z"})
    for i in range(5):
        events.append({"agent_id": f"normal_{i}", "event_type": "msg", "timestamp": "2025-01-01T11:00:00Z"})
    result = detect_outliers(events, z_threshold=1.5)
    text = format_outlier_text(result)
    assert "Outlier Detection Report" in text
    assert "outlier_agent" in text


def test_no_outliers_text():
    events = [{"agent_id": "a1", "timestamp": "2025-01-01T10:00:00Z"}]
    result = detect_outliers(events)
    text = format_outlier_text(result)
    assert "No outliers detected" in text


def test_load_and_detect(tmp_path):
    events = []
    for i in range(30):
        events.append({"agent_id": "heavy", "timestamp": "2025-01-01T10:00:00Z"})
    events.append({"agent_id": "light", "timestamp": "2025-01-01T11:00:00Z"})
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events))
    result = load_and_detect(f, z_threshold=1.0)
    assert result["total_events"] == 31


def test_single_agent_no_crash():
    events = [{"agent_id": "solo", "timestamp": "2025-01-01T10:00:00Z"}]
    result = detect_outliers(events)
    assert result["summary"]["agent_outlier_count"] == 0
